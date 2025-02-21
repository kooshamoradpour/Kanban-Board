import { UserLogin } from "../interfaces/UserLogin";
import axios from "axios";


const login = async (userInfo: UserLogin) => {
  // TODO: make a POST request to the login route
  try {
    const response = await axios.post("https://your-api.com/login", userInfo, {
      headers: { "Content-Type": "application/json" },
    });

    return response.data; // Usually contains the token or user details
  } catch (error: any) {
    console.error("Login failed:", error.response?.data || error.message);
    throw error; // Rethrow for the calling function to handle
  }
}



export { login };
