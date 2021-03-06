const messages_model=require('../models/messages.model.js');

class Messages{
	insert(message, resolve){
		console.log('insert message');

		let new_message=new messages_model(
			message
		);

		console.log("message to save new message: ", new_message);
		new_message.save(function(err, result){
			if (err){
				console.log(err);
				resolve({status: false});
			}
			else{
				//message
				//sender
				//receiver
				console.log("Message inserted: ", result)
				resolve({status: true, msgObject: result});
			}
		});
	}

	retreive(){
		console.log('retreive message');
	}

	update(){
		console.log('update message');
	}

	delete(){
		console.log('delete message');
	}
}

// Export the component
module.exports = Messages
