import mongoose, { Schema } from 'mongoose';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';


const userSchema = new Schema(
    {
        username: {
            type: String,
            required: true,
            index: true
        },
        email: {
            type: String,
            required: true,
            unique: true,
            trim: true
        },
        password: {
            type: String,
            required: [true, 'Password is required']
        },
        fullName: {
            type: String,
            required: true,
            trim: true,
            index: true
        },
        profileImage: {
            type: String
        },
        refreshToken: {
            type: String
        }
    },
    { timestamps: true }
);

userSchema.pre("save", async function (next) {
    if (this.isModified('password')) {//return next()
        this.password = await bcrypt.hash(this.password, 12)
    } .0
    next()
})

userSchema.methods.isPasswordCorrect = async function (password) {
    return await bcrypt.compare(password, this.password)
}

userSchema.methods.generateAccessToken = function () {
    return jwt.sign(
        {
            _id: this._id,
            email: this.email,
            username: this.username,
            fullName: this.fullName
        },
        process.env.ACCESS_TOKEN_SECRET,
        {
            expiresIn: process.env.ACCESS_TOKEN_EXPIRY // Corrected
        }
    )
}

userSchema.methods.generateRefreshToken = function () {
    return jwt.sign(
        {
            _id: this._id,
        },
        process.env.REFRESH_TOKEN_SECRET,
        {
            expiresIn: process.env.REFRESH_TOKEN_EXPIRY // Corrected
        }
    )
}

export const User = mongoose.model('User', userSchema);
