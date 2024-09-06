const mongoose = require('mongoose')

mongoose.connect('mongodb://localhost:27017/blog-app')

const userSchema = new mongoose.Schema({
    firstName :{
        type: String,
        required: true
    },
    lastName :{
        type: String,
        required: true
    },
    username :{
        type: String,
        required: true,
        unique: true
    },
    email :{
        type: String,
        required: true,
        unique: true
    },
    password:{
        type: String,
        required: true
    },
    post :[{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'post'
    }]
}, {timestamps: true})

const user = new mongoose.model('user',userSchema)
module.exports = user