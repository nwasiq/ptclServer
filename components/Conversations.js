const conversation_model=require('../models/conversations.model.js');

class Conversations{
	insert(participants, resolve){
		var new_conversation=new conversation_model({
			participants: {
				known: participants
			}
		});

		try{
			new_conversation.save(function(err, results){
				if (err){
					resolve({status: false});
				}
				else{
					resolve({status: true, conversationId: results._id});
				}
			});
		}
		catch(err){
			console.log(err);
		}
	}

	retreive(){
		console.log('retreive conversation');
	}

	update(){
		console.log('update conversation');
	}

	delete(){
		console.log('delete conversation');
	}
}

// Export the component
module.exports = Conversations