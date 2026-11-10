export async function register() {
  // Explicit runtime opt-in; builds and both DEMO targets leave it disabled.
  if (process.env.NEXT_RUNTIME === "nodejs" && process.env.APP_MODE === "server" && process.env.STUDIO_TELEGRAM_WORKER === "1") {
    const { startTelegramRuntime } = await import("./server/telegram/runtime");
    startTelegramRuntime(); // Never await Telegram/network before accepting bookings.
  }
}
