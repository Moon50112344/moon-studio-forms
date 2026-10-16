
import { initializeApp } from "https://www.gstatic.com/firebasejs/11.6.0/firebase-app.js";
import {
  getAnalytics,
  isSupported
} from "https://www.gstatic.com/firebasejs/11.6.0/firebase-analytics.js";
import { getAuth } from "https://www.gstatic.com/firebasejs/11.6.0/firebase-auth.js";

const firebaseConfig = {
  apiKey: "AIzaSyCoBpOgDMQSzE8TC8Xrpm5Cll8N8CJtEeA",
  authDomain: "moon-studio-forms.firebaseapp.com",
  projectId: "moon-studio-forms",
  storageBucket: "moon-studio-forms.firebasestorage.app",
  messagingSenderId: "681576741945",
  appId: "1:681576741945:web:79edf661f310501cad61e8",
  measurementId: "G-9DWYWNDH5D"
};

const app = initializeApp(firebaseConfig);
export const auth = getAuth(app);

export async function startAnalytics() {
  if (typeof window === "undefined") return;

  try {
    if (await isSupported()) {
      return getAnalytics(app);
    }
  } catch (error) {
    console.warn("Firebase Analytics is unavailable.");
  }

  return null;
}
