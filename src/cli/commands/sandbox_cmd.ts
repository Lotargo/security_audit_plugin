import { DockerRunner } from '../../docker/runner.js';
import { green, red, yellow, bold, cyan } from 'colorette';

export async function startSandboxCmd(): Promise<void> {
  console.log(bold(cyan('\nStarting Security Audit Sandbox container...')));
  const runner = new DockerRunner();

  if (!runner.isDockerAvailable()) {
    console.error(red('Docker is not running. Please start Docker daemon first.'));
    process.exit(1);
  }

  try {
    await runner.ensureRunning();
    console.log(bold(green('✔ Sandbox container is ACTIVE and healthy on http://127.0.0.1:9999\n')));
  } catch (err: any) {
    console.error(red(`Failed to start sandbox: ${err.message}`));
    process.exit(1);
  }
}

export async function stopSandboxCmd(): Promise<void> {
  console.log(bold(yellow('\nStopping Security Audit Sandbox container...')));
  const runner = new DockerRunner();
  runner.stop();
  console.log(bold(green('✔ Sandbox container STOPPED.\n')));
}

export async function resetSandboxCmd(): Promise<void> {
  console.log(bold(yellow('\nPerforming Hard Reset on Security Audit Sandbox...')));
  const runner = new DockerRunner();

  if (!runner.isDockerAvailable()) {
    console.error(red('Docker is not running.'));
    process.exit(1);
  }

  try {
    await runner.hardReset();
    console.log(bold(green('✔ Sandbox container cleanly RECREATED and ready on http://127.0.0.1:9999\n')));
  } catch (err: any) {
    console.error(red(`Hard reset failed: ${err.message}`));
    process.exit(1);
  }
}
