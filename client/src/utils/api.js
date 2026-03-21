import axios from "axios";

const api = axios.create({
  baseURL: "https://ghostrecon-api-dju7.onrender.com",
});

api.interceptors.request.use((config) => {
  const token = localStorage.getItem("gr_token");
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

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
