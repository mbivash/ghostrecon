import axios from "axios";

const api = axios.create({
  baseURL: "http://localhost:5000",
});

// Automatically attach token to every request
api.interceptors.request.use((config) => {
  const token = localStorage.getItem("gr_token");
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// If token expires redirect to login
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem("gr_token");
      localStorage.removeItem("gr_user");
      window.location.href = "/login";
    }
    return Promise.reject(error);
  },
);

export default api;
