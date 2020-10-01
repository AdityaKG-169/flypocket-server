require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const morgan = require("morgan");
const helmet = require("helmet");
const Users = require("./Models/Users");
const Cards = require("./Models/Cards");
const crypto = require("crypto");
const PORT = process.env.PORT;

const app = express();
app.use(
	cors({
		origin: "http://localhost:3000",
	})
);
app.use(bodyParser.json());
app.use(morgan("tiny"));
app.use(helmet());

const algorithm = "aes256";
const key = process.env.KEY;

const verifyToken = async (req, res, next) => {
	const { authorization } = req.headers;
	if (!authorization)
		return res.status(401).json({ error: "You Must be Logged In to Continue" });
	const token = authorization.replace("Bearer ", "");
	jwt.verify(token, process.env.TOKEN_SECRET, async (err, payload) => {
		if (err)
			return res
				.status(401)
				.json({ error: "You Must be Logged In to Continue" });
		const { id } = payload;
		const fetchedUser = await Users.findById(id);
		try {
			req.user = fetchedUser;
			next();
		} catch (err) {
			res.status(400).json({ error: "Unable to Verify User." });
		}
	});
};

mongoose.connect(process.env.MONGO_URI, {
	useNewUrlParser: true,
	useUnifiedTopology: true,
});

app.post("/register", async (req, res) => {
	let { email, password } = req.body;
	if (!email || !password)
		return res.status(400).json({ error: "Please Fill All the Details!" });
	if (password.length < 6)
		return res
			.status(400)
			.json({ error: "Password must be 6 Characters long!" });

	password = await bcrypt.hash(password, 10);
	try {
		const mailformat = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*$/;
		if (email.match(mailformat)) {
			const checkUser = await Users.findOne({ email });
			if (checkUser)
				return res.status(400).json({ error: "User Already Exists" });
			const saveUser = new Users({ email, password });
			const savedUser = await saveUser.save();
			try {
				if (savedUser.id) {
					const token = jwt.sign(saveUser.id, process.env.JWT_SECRET);
					res.status(200).json({ token });
				} else {
					res.status(400).json({ error: "Error Creating User. Try Again!" });
				}
			} catch (err) {
				res.status(400).json({ error: "Error Creating User. Try Again!" });
			}
		} else {
			res.status(400).json({ error: "Please fill a valid Email!" });
		}
	} catch (err) {
		res.status(400).json({ error: "Error Creating User. Try Again!" });
	}
});

app.post("/login", async (req, res) => {
	let { email, password } = req.body;
	if (!email || !password)
		return res.status(400).json({ error: "Please Fill All the Details!" });
	if (password.length < 6)
		return res
			.status(400)
			.json({ error: "Password must be 6 Characters long!" });

	const user = await Users.findOne({ email });
	try {
		if (!user)
			return res.status(400).json({ error: "Wrong Email or Password!" });

		isPasswordTrue = await bcrypt.compare(password, user.password);
		try {
			if (isPasswordTrue) {
				const token = jwt.sign(user.id, process.env.JWT_SECRET);
				return res.status(200).json({ token });
			} else return res.status(400).json({ error: "Wrong Email or Password!" });
		} catch (err) {
			res.status(400).json({ error: "Error Logging In! Please try Again!" });
		}
	} catch (err) {
		res.status(400).json({ error: "Error Logging In! Please try Again!" });
	}
});

app.post("/new", verifyToken, async (req, res) => {
	let { title, reference, password, description } = req.body;
	const addedBy = req.id;
	if (!title) return res.status(400).json({ error: "Enter the Title!" });

	let cipher = crypto.createCipher(algorithm, key);
	password = cipher.update(password, "utf8", "hex") + cipher.final("hex");
	description = cipher.update(description, "utf8", "hex") + cipher.final("hex");
	title = cipher.update(title, "utf8", "hex") + cipher.final("hex");
	reference = cipher.update(reference, "utf8", "hex") + cipher.final("hex");

	const newCard = new Cards({
		title,
		reference,
		password,
		description,
		addedBy,
	});
	const saveCard = await newCard.save();
	try {
		res.status(200).json({ message: "New Card Created!" });
	} catch (err) {
		res.status(400).json({ err: "Unable to add Card! Try again!" });
	}
});

app.get("/cards", verifyToken, async (req, res) => {
	const cards = await Cards.find({ addedBy: req.id });
	try {
		if (cards) {
			let { addedOn, title, description, reference } = cards;
			var decipher = crypto.createDecipher(algorithm, key);
			title = decipher.update(title, "hex", "utf8") + decipher.final("utf8");
			description =
				decipher.update(description, "hex", "utf8") + decipher.final("utf8");
			reference =
				decipher.update(reference, "hex", "utf8") + decipher.final("utf8");
			return res
				.status(200)
				.json({ message: { addedOn, title, description, reference } });
		} else return res.status(200).json({ message: "No Cards Yet!" });
	} catch (err) {
		res.status(400).json({ error: "Unable to Get Cards! Please Try Again!" });
	}
});

app.get("/card/:cardId", verifyToken, async (req, res) => {
	const card = await Cards.findById(req.params.cardId);
	try {
		if (!card) return res.status(400).json({ err: "Card Not Found!" });
		let password = card.password;
		var decipher = crypto.createDecipher(algorithm, key);
		password =
			decipher.update(password, "hex", "utf8") + decipher.final("utf8");
	} catch (err) {
		res.status(400).json({ error: "Card Not Found!" });
	}
});

app.get("/profile", verifyToken, async (req, res) => {
	if (!req.email) return res.status(400).json({ error: "No User Found!" });
	res.status(200).json({ message: req.email });
});

app.delete("/card/:cardId", verifyToken, async (req, res) => {
	const card = await Cards.findByIdAndDelete(req.params.cardId);
	try {
		if (!card) return res.status(400).json({ error: "Card Not Found!" });
		res.status(200).json({ message: "Card Deleted Successfully!" });
	} catch (err) {
		res.status(400).json({ error: "Card Not Found!" });
	}
});

app.listen(PORT, () => console.log(`Server is running on Port ${PORT}`));
