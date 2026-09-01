import { DockerRunner, DEFAULT_REGISTRY_IMAGE } from '../../docker/runner.js';
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

export async function pullSandboxCmd(options: { image?: string } = {}): Promise<void> {
  const targetImage = options.image || DEFAULT_REGISTRY_IMAGE;
  console.log(bold(cyan(`\nPulling Security Audit Sandbox image: ${targetImage}...`)));
  const runner = new DockerRunner();

  if (!runner.isDockerAvailable()) {
    console.error(red('Docker daemon is not running. Please start Docker Desktop or dockerd.'));
    process.exit(1);
  }

  const ok = runner.pullImage(targetImage);
  if (ok) {
    console.log(bold(green(`✔ Successfully pulled and tagged sandbox image: ${targetImage}\n`)));
  } else {
    console.error(red(`\n✖ Failed to pull image from ${targetImage}. Try running 'security-audit build-sandbox' instead.`));
    process.exit(1);
  }
}

export async function buildSandboxCmd(options: { path?: string } = {}): Promise<void> {
  console.log(bold(cyan('\nBuilding Security Audit Sandbox container image locally...')));
  const runner = new DockerRunner();

  if (!runner.isDockerAvailable()) {
    console.error(red('Docker daemon is not running. Please start Docker Desktop or dockerd.'));
    process.exit(1);
  }

  const ok = runner.buildImage(options.path);
  if (ok) {
    console.log(bold(green('✔ Successfully built sandbox Docker image: security-audit-sandbox:latest\n')));
  } else {
    console.error(red('\n✖ Local Docker build failed.'));
    process.exit(1);
  }
}
