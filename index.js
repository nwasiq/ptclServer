const server = require('http').createServer().listen(3000);
const fs = require('fs');
const io = require('socket.io')(server, {
	'pingInterval':10000,
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
	    	}).then(function(response){
	    		if (response.status){
	    			socketId=response.socketId;
	    			userId=response.userId;
	    			new Promise(function(resolve, reject){
	    				conversations.insert([ { user_id: response.userId, phone_number: response.number }, { user_id: conversation.id, phone_number: conversation.myNumber }], resolve);
					}).then(function (response2) {
						console.log("response2: ", response2)
						conversationId = response2.conversationId;
						new Promise(function (resolve, reject) {
							messages.insert({ conversationId: response2.conversationId, type: 'text', sender: conversation.id, receiver: userId, content: conversation.msg }, resolve);
						}).then(function (response3) {
							console.log("MESSAGE EMITTED TO USER!")
							console.log(response3)
							socket.to(socketId).emit('newConversation', response3);
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

  	socket.on('message', function(text) {
    	console.log('message received');

    	socketId='m-UJ2r4sV8lxYVAkAAAB';

    	socket.to(connected_users[1]).emit('incomingMessage', text+socket.id);
    	//const receiverSocketId = mobileSockets[receiver.id];
    	//socket.to(receiverSocketId).emit('incomingMessage', message);
  	});

		socket.on('disconnect', function(){
			//users.unsetSocket();
		});
});
