const mongoose = require('mongoose');
const Schema = mongoose.Schema;

let MessagesSchema = new Schema({
	conversation_id: 		String,
	type: 					{type: String, required: true},
    sender: 	 			{type: String, required: true, unique: true, max: 100},
    receiver: 				{type: String, max: 250},
    content: 				{type: String},
    delivered: 				{type: Boolean, required: true, default: false },
    sent_time: 				{type: Date, required: true, default: Date.now },
    delivered_time:			{type: Date, required: true, default: Date.now }
});


// Export the model
module.exports = mongoose.model('Messages', MessagesSchema);