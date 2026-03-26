import axios from "axios";

const rawApiUrl = import.meta.env.VITE_API_URL?.trim();
const isProductionBuild = import.meta.env.PROD;

const baseURL =
  rawApiUrl || (isProductionBuild ? "/api" : "http://localhost:5000");

if (isProductionBuild && !rawApiUrl) {
  console.warn(
    "[GhostRecon] VITE_API_URL is not set. Falling back to '/api'. Set VITE_API_URL in hosting env.",
  );
}

const api = axios.create({
  baseURL,
  timeout: 20000,
});

api.interceptors.request.use((config) => {
  const token = localStorage.getItem("gr_token");
  if (token) config.headers.Authorization = `Bearer ${token}`;
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
