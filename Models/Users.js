const mongoose = require("mongoose");
const Schema = mongoose.Schema;

const Users = new Schema({
	email: {
		type: String,
		required: true,
	},
	password: {
		type: String,
		required: true,
	},
	joined: {
		type: Date,
		default: Date.now,
	},
});

module.exports = mongoose.model("Users", Users);