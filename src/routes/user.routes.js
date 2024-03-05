import { Router } from "express";
import { verifyJWT } from "../middlewares/auth.middleware.js";
import { upload } from "../middlewares/multer.middleware.js";

//router import
import {
    registerUser,
    loginUser,
    logoutUser,
    refreshAccessToken,
    changeCurrentPassword,
    getCurrentUser,
    updateAccountDetail,
    updateProfileImage
} from "../controller/user.controller.js";


//router declaration
const router = Router()
router.route("/register").post(
    upload.fields([
        {
            name: "profileImage",
            maxCount: 1
        },
    ]),
    registerUser
)



router.route("/login").post(loginUser)
router.route("/logout").post(verifyJWT, logoutUser)
router.route("/refresh-token").post(refreshAccessToken)
router.route("/change-password").post(verifyJWT, changeCurrentPassword)
router.route("/current-user").get(verifyJWT, getCurrentUser)
router.route("/update-accoun").patch(verifyJWT, updateAccountDetail)
router.route("/profileImage").patch(verifyJWT, upload.single("profileImage"), updateProfileImage)



export default router