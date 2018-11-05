const messages_model=require('../models/messages.model.js');

class Messages{
	insert(message, resolve){
		console.log('insert message');

		new_message=new messages_model({
			message
		});

		new_message,save(function(err, result){
			if (err){
				console.log(err);
				resolve({status: false});
			}
			else{
				//message
				//sender
				//receiver
				resolve({status: true,});
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
