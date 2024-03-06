import dotenv from "dotenv"
import connectDB from "./db/index.js";
import { app } from "./app.js";


dotenv.config({
    path: './env'
})


connectDB()
    .then(() => {
        app.listen(process.env.PORT || 9000), () => {
            console.log(` Server is running at port : http://127.0.0.1:${process.env.PORT}`);
        }
        app.on("error", (error) => {
            console.log("ERR: ", error);
            throw error
        })
    })
    .catch((err) => {
        console.log(`MONGO db connection failed !!! `, err);
    })