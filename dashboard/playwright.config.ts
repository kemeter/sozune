import { defineConfig, devices } from '@playwright/test';

// Functional tests of the dashboard against a real Sōzune: the debug binary
// serves the dashboard built in `build/` and its API, with the routes of
// `e2e/fixtures/entrypoints.yaml`.
export default defineConfig({
  testDir: './e2e',
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: [['list']],
  use: {
    baseURL: 'http://127.0.0.1:23038',
    trace: 'retain-on-failure'
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  webServer: {
    command: 'bun run build && cargo run --quiet --manifest-path ../Cargo.toml --bin sozune',
    env: { CONFIG_PATH: 'e2e/fixtures/config.yaml', RUST_LOG: 'sozune=info' },
    url: 'http://127.0.0.1:23038',
    reuseExistingServer: false,
    timeout: 600_000,
    stdout: 'ignore',
    stderr: 'pipe'
  }
});
