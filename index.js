const server = require('http').createServer().listen(3000);
const fs = require('fs');
const io = require('socket.io')(server, {
	'pingInterval':20000,
	'pingTimeout':25000
});

const Users= require('./components/Users.js');
const users=new Users;

const Conversations= require('./components/Conversations.js');
const conversations= new Conversations;

const Messages= require('./components/Messages.js');
const messages= new Messages;

const mongoose = require('mongoose');
let dev_db_url = 'mongodb://127.0.0.1:27017/ptclDB';
let mongoDB = process.env.MONGODB_URI || dev_db_url;
mongoose.connect(mongoDB);
mongoose.Promise = global.Promise;
let db = mongoose.connection;
db.on('error', console.error.bind(console, 'MongoDB connection error:'));

//const mobileSockets = {};
let connected_users=[];

console.log('server up');
io.on('connection', socket => {
	console.log('connection established');

	socket.emit('is_user', JSON.stringify({hello:'who art thou?'}));

	socket.on('pstn', function(user) {
    	console.log('phone_number received');

    	let socketId=socket.id;

    	try{
			new Promise(function(resolve, reject){
	    		users.insert(user, socketId, resolve);
	    	}).then(function(response){
					console.log('emit offers');
	    		socket.emit('offers', JSON.stringify({id: response.id, offers: ['agent', 'landline', 'mobile', 'sms', 'email']}));
	    	});
	    }
	    catch(err){
	    	console.log(err);
	    }
  	});

  	socket.on('selected_offer', function(user) {
    	console.log('selected_offer received');conversations

    	try{
			new Promise(function(resolve, reject){
	    		users.otp(user, resolve, false);
	    	}).then(function(response){
	    		socket.emit('pin', JSON.stringify(response));
	    	});
	    }
	    catch(err){
	    	console.log(err);
	    }
  	});

  	socket.on('pin_verification', function(user) {
    	console.log('pin received');

    	try{
			new Promise(function(resolve, reject){
	    		users.otp(user, resolve, true);
	    	}).then(function(response){
    			socket.emit('pin_verification', JSON.stringify(response));
	    	});
	    }
	    catch(err){
	    	console.log(err);
	    }
  	});

  	socket.on('user', function(user) {
    	console.log('user received', user);

    	let socketId=socket.id;

    	console.log(socketId);

    	try{
			new Promise(function(resolve, reject){
	    		users.setSocket(user, socketId, resolve);
	    	}).then(function(response){
	    		if (response.status){
	    			socket.emit('online', JSON.stringify({online: true}));
	    		}
	    	});
	    }
	    catch(err){
	    	console.log(err);
	    }
  	});

		socket.on('contacts', function(data) {
			var contacts=data.contacts;
			console.log('contacts received');

    	try{
			new Promise(function(resolve, reject){
	    		users.addContacts(data, resolve);
	    	}).then(function(response){
	    		if (response.status){
					// console.log("Send messasge to these users that his friend has joined ptcl smartlink: ");
					// console.log(response.updatedUsers);
					// console.log("The friend who has joined basically: ", response.updatedUsers[0].friendName);
					for(var i = 0; i < response.updatedUsers.length; i++){
						socket.to(response.updatedUsers[i].socket_id).emit('friendNoti', response.updatedUsers[i].friendName);
					}
	    			socket.emit('contacts', response.contacts);
	    		}
	    	});
	    }
	    catch(err){
	    	console.log(err);
	    }
  	});

  	socket.on('new_conversation', function(conversation) {
		console.log('conversation received: ', conversation);

    	let socketId;
    	let userId;
		let conversationId;
		conversation.contactNumber = conversation.contactNumber.replace(/\s/g, '')
		console.log("Beginning new convo!");
    	try{
			new Promise(function(resolve, reject){
				users.getUser(conversation.contactNumber, resolve);
	    	}).then(function(user){
	    		if (user.status){
	    			socketId=user.socketId;
	    			userId=user.userId;
	    			new Promise(function(resolve, reject){
	    				conversations.insert([ { user_id: user.userId, phone_number: user.number }, { user_id: conversation.id, phone_number: conversation.myNumber }], resolve);
					}).then(function (convo) {
						console.log("response2: ", convo)
						conversationId = convo.conversationId;
						new Promise(function (resolve, reject) {
							messages.insert({ conversation_id: convo.conversationId, type: 'text', sender: conversation.id, receiver: userId, content: conversation.msg }, resolve);
						}).then(function (messageObject) {
							// console.log("MESSAGE EMITTED TO USER!")
							// console.log(messageObject)
							// console.log('Conversation ID: ', messageObject.conversation_id);

							messageObject.senderNumber = conversation.myNumber
							console.log("sender Number: ",messageObject.senderNumber)
							socket.to(socketId).emit('newConversation', messageObject);
							socket.emit('conversation_id', messageObject.msgObject.conversation_id);
						})
					})
				}
				else{
					console.log("No user found to send message to. Should send an sms")
				}
			})
	    }
	    catch(err){
	    	console.log(err);
	    }
  	});

	  // msg object contains type, content and conversation_id, sender_id (auth token / online ID)
  	socket.on('message', function(msgObject) {
    	console.log('message received: ', msgObject);

		var receiverID;
		var conversationID = msgObject.text.conversation_id;
		var senderID = msgObject.text.sender_id;
		new Promise(function(resolve, reject) {
			conversations.retreive(conversationID, resolve, reject);
		}).then(function(conversation){
			if(conversation){
				if (conversation.participants.known[0].user_id == senderID){
					receiverID = conversation.participants.known[1].user_id;
				}
				else{
					receiverID = conversation.participants.known[0].user_id;
				}
				new Promise(function(resolve, reject){
					messages.insert({ conversation_id: conversationID, type: msgObject.text.type, sender: senderID, receiver: receiverID, content: msgObject.text.content }, resolve);
				}).then(function(message){
					if(message.status){
						console.log("message saved to db: ", receiverID);
						new Promise(function(resolve, reject){
							users.getUserSocket(receiverID, resolve);
						}).then(function(user){
							if(user.status){
								socket.to(user.socketId).emit("newMessage", {msgObject: message.msgObject, senderNumber: msgObject.text.sender_number})
							}
							else{
								console.log("An error occured, failed to retrieve receiver socket");
							}
						})

					}
					else{
						console.log("An error occured");
					}
				})
			}
		}, function(err){
			console.log("conversation did not retrieve. err occured", err)
		})
    	// socketId='m-UJ2r4sV8lxYVAkAAAB';

    	// socket.to(connected_users[1]).emit('incomingMessage', text+socket.id);
    	//const receiverSocketId = mobileSockets[receiver.id];
    	//socket.to(receiverSocketId).emit('incomingMessage', message);
  	});

	socket.on('disconnect', function () {
		//users.unsetSocket();
	});

	function getRoomNumberForCalls() {
		return Math.floor(100000 + Math.random() * 900000);
	}

	/**
	 * TODO: callObject needs to include: receiverNumber, callerNumber
	 */
	socket.on('call', function(callObject){
		console.log("Call object: ", callObject);
		console.log("this number needs to be ringed: ", callObject.receiverNumber);
		new Promise((resolve, reject) => {
			console.log('')
			users.getUser(callObject.receiverNumber, resolve)
		}).then((user) => {
			var callObj = {
				callerNumber: callObject.callerNumber,
				roomId: getRoomNumberForCalls(),
				type: callObject.type
			}
			console.log("This object is being emitted to incoming calls: ", callObj);
			socket.to(user.socketId).emit('incomingCall', callObj);
			// socket.emit('onCall', callObject.onCall);
		})
	});

	socket.on('callAccepted', function(callObject){
		console.log('callAccepted: Room ID: ', callObject.roomId);
		console.log('callAccepted: Number to accept call: ', callObject.callerNumber);

		new Promise((resolve, reject) => {
			users.getUser(callObject.callerNumber, resolve);
		}).then((user) => {
			socket.to(user.socketId).emit('outgoingCallConnected', callObject.roomId);
		})
		var callObj = {
			type: callObject.type,
			roomId: callObject.roomId
		}
		socket.emit('outgoingCallConnected', callObj);
	});
});
