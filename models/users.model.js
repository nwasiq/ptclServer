const mongoose = require('mongoose');
const ObjectId = require('mongodb').ObjectID;
const Schema = mongoose.Schema;

let UsersSchema = new Schema({
    phone_number: 			{type: String, required: true, unique: true, max: 100},
    name: 					{type: String, max: 250},
    profile_picture: 		{type: String, max: 250},
    contacts: 				[{
      onlineId:          {type: String},
      _id:                {type: Number},
    	name: 					    {type: String, max: 100},
    	profile_picture: 		{type: String, max: 250},
    	phone_number: 			[{
        onlineId:          {type: String},
        _id:                {type: Number},
    		type: 					    {type: String, max: 100},
    		phone_number: 			{type: String, max: 100}
    	}]
    }],
    devices: 				[{
    	device_id: 				{type: String},
    	device_mac_address: 	{type: String},
    	device_manufacturer: 	{type: String},
    	device_model: 			{type: String},
    	device_brand: 			{type: String},
    	device_api_level: 		{type: String},
    	device_serial: 			{type: String},
    	phone_number: 			{type: String}
    }],
    socket_id: 				{type: String},
    verified: 				{type: Boolean, default: false},
    blocked: 				{type: Boolean, default: false},
    pin: 					String,
    join_time: 				{type: Date, required: true, default: Date.now },
    verification_time:		{type: Date, required: true, default: Date.now },
    login_time: 			{type: Date, required: true, default: Date.now }
});


// Export the model
module.exports = mongoose.model('Users', UsersSchema);
