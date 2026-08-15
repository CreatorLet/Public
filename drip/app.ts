import path from 'path';
import { fileURLToPath } from 'url';
import express, {
  type Express,
  type Request,
  type Response,
  type NextFunction,
} from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import pinoHttp from "pino-http";
import router from "./routes/index.js";
import { logger } from "./lib/logger.js";
import { initStorage } from "./lib/supabase.js";

const app: Express = express();

// Trust Replit's reverse proxy (needed for rate-limit IP detection)
app.set("trust proxy", 1);

// Security headers
app.use(
  helmet({
    crossOriginResourcePolicy: { policy: "cross-origin" },
  })
);

// CORS — allow Replit preview/deploy domains and localhost
const ALLOWED = [/\.replit\.dev$/, /\.repl\.co$/, /^http:\/\/localhost:\d+$/];
app.use(
  cors({
    origin(origin, cb) {
      if (!origin) return cb(null, true);
      if (ALLOWED.some((r) => r.test(origin))) return cb(null, true);
      cb(null, false);
    },
    credentials: true,
  })
);

// Rate limiting — stricter on auth to prevent brute-force / OTP spam
app.use(
  "/api/auth/",
  rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 30,
    standardHeaders: true,
    legacyHeaders: false,
    message: { message: "Too many authentication attempts, please try again in 15 minutes." },
  })
);

// General API rate limit
app.use(
  "/api/",
  rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 300,
    standardHeaders: true,
    legacyHeaders: false,
    message: { message: "Too many requests, please try again later." },
  })
);

// Request logging
app.use(
  pinoHttp({
    logger,
    serializers: {
      req(req) {
        return { id: req.id, method: req.method, url: req.url?.split("?")[0] };
      },
      res(res) {
        return { statusCode: res.statusCode };
      },
    },
  })
);

// Tight body limit for most routes; image-upload routes raise it themselves
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true, limit: "1mb" }));

// Larger body limit for routes that accept base64 images
// Applied before the route so individual image-upload handlers can rely on it
app.use("/api/listings", express.json({ limit: "50mb" }));
app.use("/api/auth/avatar", express.json({ limit: "10mb" }));
app.use("/api/admin/ads", express.json({ limit: "20mb" }));
app.use("/api/admin/listings", express.json({ limit: "50mb" }));

app.use("/api", router);

// Global error handler
app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
  logger.error(err, "Unhandled error");
  res.status(500).json({ message: "Internal server error" });
});

// Initialise Supabase Storage buckets (runs once at startup, non-blocking)
initStorage().catch((e) => logger.warn(e, "initStorage failed"));


const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Serve static files from the frontend build
const frontendPath = path.join(__dirname, '../../property-lo/dist');
app.use(express.static(frontendPath));

app.get('*', (req, res, next) => {
  if (req.path.startsWith('/api')) return next();
  res.sendFile(path.join(frontendPath, 'index.html'));
});

export default app;
