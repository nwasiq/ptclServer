const mongoose = require('mongoose');
const Schema = mongoose.Schema;

let ConversationSchema = new Schema({
    name: 				{type: String, max: 250},
    participants: 		[{
    	known: 				[{
    		user_id: 		String,
    		phone_number: 	String
    	}],
    	unknown: 		[{
    		phone_number: 	{type: String}
    	}]
    }]
});


// Export the model
module.exports = mongoose.model('Conversation', ConversationSchema);