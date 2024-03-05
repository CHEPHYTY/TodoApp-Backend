import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiError } from "../utils/ApiErrors.js"
import { User } from "../models/user.model.js"
import { uploadOnCloudinary } from "../utils/cloudinary.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import jwt from "jsonwebtoken";
import mongoose from "mongoose";


const generateAccessAndRefereshTokens = async (userId) => {
    try {
        const user = await User.findById(userId)
        const accessToken = user.generateAccessToken()
        const refreshToken = user.generateRefreshToken()
        user.refreshToken = refreshToken
        await user.save({ validateBeforeSave: false })

        return { accessToken, refreshToken }
    } catch (error) {
        // throw new ApiError(500, "Something went wrong while genrating refersh and success Token")
        throw new ApiError(500, `${error}`)
    }
}


const registerUser = asyncHandler(async (req, res) => {

    // get user details from frontend
    // validation - not empty
    // check if user already exists: username, email
    // check for images, check for avatar
    // upload them to cloudinary, avatar
    // create user object - create entry in db
    // remove password and refresh token field from response
    // check for user creation
    // return res

    // 1. get user details from frontend
    const { fullName, email, username, password } = req.body

    // 2.validation - not empty
    if ([fullName, email, username, password].some((field) => field?.trim() == "")) {
        throw new ApiError(400, "All fields are required")
    }


    // 3.check if user already exists: username, email
    const existedUser = await User.findOne({
        $or: [{ username }, { email }]
    })
    if (existedUser) {
        throw new ApiError(400, "User with email or username already exists")
    }
    // 4.upload them to cloudinary, avatar
    // const avatarLocalPath = req.files?.avatar[0]?.path;

    const profileImagePath = req.files?.profileImage?.[0]?.path;

    // let profileImagePath;
    // if (req.files && req.files.profileImage && Array.isArray(req.files.profileImage) && req.files.profileImage.length > 0) {
    //     profileImagePath = req.files.profileImage[0].path;
    // }
    if (!profileImagePath) {
        throw new ApiError(400, "Profile Image is required")
    }

    // 5.upload them to cloudinary, avatar
    const profileImage = await uploadOnCloudinary(profileImagePath)

    if (!profileImage) {
        throw new ApiError(400, "Profile Image is required")
    }

    // 6.create user object - create entry in db
    const user = await User.create({
        fullName,
        profileImage: profileImage.url,
        email,
        password,
        username: username
    })

    // 7.remove password and refresh token field from response
    const createdUser = await User.findById(user._id).select(
        "-password -refreshToken"
    )

    // 8.check for user creation
    if (!createdUser) {
        throw new ApiError(500, "Something wend wrong while registering the user")
    }


    // 9.return res
    return res.status(201).json(
        new ApiResponse(200, createdUser, "User registed succefully ")
    )
})


const loginUser = asyncHandler(async (req, res) => {
    // req body -> data
    // username or email
    //find the user
    //password check
    //access and referesh token
    //send cookie


    // 1.req body -> data
    const { email, username, password } = req.body
    // 2.username or email

    if (!(username || email)) {
        throw new ApiError(400, "Username or Email is required")
    }

    //3.find the user
    const user = await User.findOne({
        $or: [{ username }, { email }]
    })

    if (!user) {
        throw new ApiError(404, "User does not Exist")
    }
    //4.password check
    // const isPasswordValid = await user.isPasswordCorrect(password);
    // if (!isPasswordValid) {
    //     throw new ApiError(401, "Invalid user credentials")
    // }

    //problem is here it is not rturning true
    const isPasswordValid = await user.isPasswordCorrect(password);
    // const isPasswordValid = await bcrypt.compare(password.trim(), user.password);


    if (!isPasswordValid) {
        // console.log(`Provided Password:${password}`);
        // console.log(`Stored Password Hash:${user.password}`); // Make sure this is a hashed password
        throw new ApiError(401, "Invalid user credentials");
    }

    const { accessToken, refreshToken } = await generateAccessAndRefereshTokens(user._id)

    //costly call 
    const loggedInUser = await User.findById(user._id).select("-password -refreshToken")

    const options = {
        httpOnly: true,
        secure: true
    }

    return res
        .status(200)
        .cookie("accessToken", accessToken, options)
        .cookie("refreshToken", refreshToken, options)
        .json(
            new ApiResponse(
                200,
                {
                    user: loggedInUser, accessToken, refreshToken
                },
                "User logged In Successfully"
            )
        )

})


const logoutUser = asyncHandler(async (req, res) => {
    await User.findByIdAndUpdate(
        req.user._id,
        {
            $unset: {
                refreshToken: 1//this removes the field from documents
            }
        },
        {
            new: true
        }
    )

    const options = {
        httpOnly: true,
        secure: true
    }

    return res
        .status(200)
        .clearCookie("accessToken", options)
        .clearCookie("refreshToken", options)
        .json(new ApiResponse(200, {}, "User Logout Succefully"))
})



const refreshAccessToken = asyncHandler(async (req, res) => {
    const incomingRefreshToken = req.cookies.refreshToken || req.body.refreshToken

    if (!incomingRefreshToken) {
        throw new ApiError(401, "unauthorized request")
    }

    try {
        const decodedToken = jwt.verify(
            incomingRefreshToken,
            process.env.REFRESH_TOKEN_SECRET
        )

        const user = await User.findById(decodedToken?._id)

        if (!user) {
            throw new ApiError(401, "Invalid refresh token")
        }

        if (incomingRefreshToken !== user?.refreshToken) {
            throw new ApiError(401, "Refresh token is expired or used")

        }

        const options = {
            httpOnly: true,
            secure: true
        }

        const { accessToken, newRefreshToken } = await generateAccessAndRefereshTokens(user._id)

        return res
            .status(200)
            .cookie("accessToken", accessToken, options)
            .cookie("refreshToken", newRefreshToken, options)
            .json(
                new ApiResponse(
                    200,
                    { accessToken, refreshToken: newRefreshToken },
                    "Access token refreshed"
                )
            )
    } catch (error) {
        throw new ApiError(401, error?.message || "Invalid refresh token")
    }
})

const changeCurrentPassword = asyncHandler(async (req, res) => {
    const { oldPassword, newPassword } = req.body

    const user = await User.findById(req.user?._id)
    const isPasswordCorrect = await user.isPasswordCorrect(oldPassword)


    if (!isPasswordCorrect) {
        throw new ApiError(400, "Invalid old Password")
    }

    user.password = newPassword
    await user.save({ validateBeforeSave: false })

    return res.status(200).json(new ApiResponse(200, {}, "Password Change Successfully "))



})

const getCurrentUser = asyncHandler(async (req, res) => {
    // const {accessToken} = req.body
    // if(!accessToken){

    // }
    return res.status(200)
        .json(new ApiResponse(200, req.user, "Current user fetched successfully"))
})


const updateAccountDetail = asyncHandler(async (req, res) => {
    const { fullName, email } = req.body

    if (!fullName || !email) {
        throw new ApiError(400, "All fields are required")
    }


    const user = await User.findByIdAndUpdate(
        req.user?._id,
        {
            $set: {
                fullName: fullName,
                email: email
            }
        },
        { new: true }
    ).select("-password")

    return res
        .status(200)
        .json(new ApiResponse(200, user, "Account details updated Successfully"))
})

const updateProfileImage = asyncHandler(async (req, res) => {
    const profileImageLocalPath = req.file?.path

    if (!profileImageLocalPath) {
        throw new ApiError(400, "Avatar file is missing")
    }

    const profileImage = await uploadOnCloudinary(profileImageLocalPath)

    if (!avatar.url) {
        throw new ApiError(400, "Error while uploading on avatar")
    }

    const user = await User.findByIdAndUpdate(
        req.user?._id,
        {
            $set: {
                profileImage: profileImage.url
            }
        },
        { new: true }
    ).select("-password")
    return res
        .status(200)
        .json(new ApiResponse(200, user, "Avatar updated Successfully"))
})

export {
    registerUser,
    loginUser,
    logoutUser,
    refreshAccessToken,
    changeCurrentPassword,
    getCurrentUser,
    updateAccountDetail,
    updateProfileImage
}