const mongoose = require("mongoose");
const Schema = mongoose.Schema;

const Cards = new Schema({
	title: {
		type: String,
		required: true,
	},
	reference: {
		type: String,
		default: "",
	},
	password: {
		type: String,
		default: "",
	},
	description: {
		type: String,
		default: "",
	},
	addedBy: {
		type: String,
		required: true,
	},
	addedOn: {
		type: Date,
		default: Date.now,
	},
});

module.exports = mongoose.model("Cards", Cards);
