const userModel=require('../models/users.model.js');
var MongoClient = require('mongodb').MongoClient;

class Users{
	async insert(user_to_insert, socketId, resolve){
		console.log('insert user');
		console.log(user_to_insert);

		user_to_insert=JSON.parse(user_to_insert);
		console.log(user_to_insert);

		try{
			userModel.find({phone_number: user_to_insert.pstn}, function(req, users){
				if (users.length==0){ //completely new user
					console.log('completely new user');
					var pin=Math.floor(1000 + Math.random() * 9000);
					var user_row=new userModel({
						phone_number: 					user_to_insert.pstn,
						devices:[{
							device_id: 						user_to_insert.device_id,
							device_mac_address: 			user_to_insert.device_mac_address,
							device_model: 					user_to_insert.device_model,
					    	device_brand: 					user_to_insert.device_brand,
					    	device_api_level: 				user_to_insert.device_api_level,
					    	device_serial: 					user_to_insert.device_serial,
					    	phone_number: 					user_to_insert.phone_number
					    }],
				    	pin: 							pin,
				    	socket_id: 						socketId
					});

					try{
						user_row.save(function(err, results){
							console.log(err);
							var id=results._id;
							resolve({status: true, type: 'new', id: id});
						});
					}
					catch(err){
						console.log(err);
					}
				}
				else{ //check if new device or not
					console.log('check if new device or not because not new user');
					userModel.find({
						phone_number: 		user_to_insert.pstn,
						devices: [{
							device_id: 			user_to_insert.device_id,
						}]
					}, function(req, devices){
						if (devices.length>0){ // pre-existing device
							console.log('Device Conflict');
							resolve({status: true, type: 'existing', id: res[0]._id});
						}
						else{ //new device
							//insert new device in existing user
						}
					});
				}
			});
		}
		catch(err){
			console.log(err);
			resolve({status: false});
		}
	}

	otp(user, resolve, verify){
		console.log(user);
		user=JSON.parse(user);
		userModel.find({_id: user.id, phone_number: user.pstn, 'devices.device_id': user.device_id }, function(req, users){
			console.log(req);
			if (users.length>0){
				console.log(users[0].pin);

				if (verify){
					if (users[0].pin==user.pin){
						users[0].set({
							verified: 				true,
							verification_time: 		Date.now()
						});
						users[0].save(function(err, updatedUser){
							if (err){
								console.log(err);
								resolve({status: false, message: 'Pin Code Could Not Be Verified!'});
							}
							else{
								resolve({status: true});
							}
						});
					}
					else{
						resolve({status: false, message: 'User Could Not Be Verified!'});
					}
				}
				else{
					resolve({status: true, selected_offer: user.selected_offer, message: 'Please Enter The Following Pin To Verify Yourself: '+users[0].pin});
				}
			}
			else{
				console.log('user not found');
				resolve({status: false, message: 'An error was encountered!'});
			}
		});
	}

	setSocket(user, socketId, resolve){
		// user=JSON.parse(user);
		console.log(user);
		userModel.find({_id: user.id, phone_number: user.pstn, 'devices.device_id': user.device_id }, function(req, users){
			console.log(req);
			if (users.length>0){
				users[0].set({
					socket_id: 				socketId,
					login_time: 			Date.now()
				});
				users[0].save(function(err, updatedUser){
					if (err){
						console.log(err);
						resolve({status: false});
					}
					else{
						resolve({status: true});
					}
				});
			}
		});
	}

	addContacts(data, resolve){
		var self=this;
		var contacts=data.contacts;
		console.log('received contacts length: ', contacts.length);
		console.log('received contacts: ', contacts);
		userModel.find({_id: data.id, phone_number: data.pstn, 'devices.device_id': data.device_id }, function(req, users){
			if (users.length>0){
				// userModel.find({_id: data.id, contacts.name:  }, function(req, users){{
					//iteraring through contacts sent by client
					for (var i=0; i<contacts.length; i++){
						if (contacts[i]==null){
							continue;
						}
						
						(function(){
							var count_primary=i;

							console.log('contact #'+count_primary+': ', contacts[count_primary]);
							contacts[count_primary]._id=parseInt(contacts[count_primary]._id, 10);

							//iterating through current contacts phone numbers
							for (var j=0; j<contacts[count_primary].phone_number.length; j++){
								(function(){
									console.log(contacts[count_primary].phone_number[count_sub]);
									var count_sub=j;
									userModel.find({phone_number: contacts[count_primary].phone_number[count_sub].phone_number.replace(/\s/g, '') }, function(err, contact){
										if (contact.length>0){
											console.log('ID: ', contact[0]._id);
											contacts[count_primary].onlineId=contact[0]._id;
											contacts[count_primary].phone_number[count_sub].onlineId=contact[0]._id;

											console.log('Contact: ', contacts[count_primary]);
										}

										if (count_sub == (contacts[count_primary].phone_number.length-1)){
											users[0].contacts.push(contacts[count_primary]);

											if (count_primary==(contacts.length-1)){
												users[0].save(function(err, updatedUser){
													if (err){
														console.log(err);
													}
													else{
														console.log('saved');
													}
												});
												resolve({status: true, contacts});
											}
										}
									});
								})();
							}
						})();
				  }
				// }
			}
		});
	}

	insertContact(id, contact, resolved){
		userModel.find({_id: id }, function(err, users){
			users[0].contacts.push(contact);
			users[0].save(function(err, updatedUser){
				if (err){
					console.log(err);
				}
				else{
					resolved(true);
				}
			});
		});
	}

	update(user, condition){
		console.log('update user');
	}

	getUser(number, resolve){
		console.log("number being searched: ", number)
		userModel.find({ phone_number: number }, function(err, users){
			if (err){
				resolve({status:false});
			}
			else{
				if(users.length == 0){
					resolve({ status: false });
				}
				resolve({ status: true, socketId: users[0].socket_id, userId: users[0]._id, number: users[0].phone_number});
			}
		});
	}

	delete(user){
		console.log('delete user');
	}
}

// Export the component
module.exports = Users
