import { DockerRunner, DEFAULT_REGISTRY_IMAGE } from '../../docker/runner.js';
import { RatchetBridge } from '../../mcp/security/ratchet_bridge.js';
import { green, red, yellow, bold, cyan } from 'colorette';

function createAuthenticatedRunner(): { runner: DockerRunner; ratchet: RatchetBridge } {
  const ratchet = new RatchetBridge();
  const runner = new DockerRunner({
    hostPubkeyHex: ratchet.getPublicKeyHex(),
    sessionKeyHex: ratchet.getSessionKeyHex(),
  });
  return { runner, ratchet };
}

export async function startSandboxCmd(): Promise<void> {
  console.log(bold(cyan('\nStarting Security Audit Sandbox container...')));
  const { runner, ratchet } = createAuthenticatedRunner();

  if (!runner.isDockerAvailable()) {
    console.error(red('Docker is not running. Please start Docker daemon first.'));
    process.exit(1);
  }

  try {
    await runner.ensureRunning(ratchet.getPublicKeyHex(), ratchet.getSessionKeyHex());
    console.log(
      bold(
        green(
          '✔ Sandbox container is ACTIVE and healthy on http://127.0.0.1:9999\n' +
            '  Note: the MCP command owns its own ephemeral trust session and will re-key/restart this container when it connects.\n'
        )
      )
    );
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
  const { runner, ratchet } = createAuthenticatedRunner();

  if (!runner.isDockerAvailable()) {
    console.error(red('Docker is not running.'));
    process.exit(1);
  }

  try {
    await runner.hardReset(ratchet.getPublicKeyHex(), ratchet.getSessionKeyHex());
    console.log(bold(green('✔ Sandbox container cleanly RECREATED and healthy.\n')));
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

  if (runner.pullImage(targetImage)) {
    console.log(bold(green(`✔ Successfully pulled and tagged sandbox image: ${targetImage}\n`)));
  } else {
    console.error(
      red(`\n✖ Failed to pull image from ${targetImage}. Try 'security-audit build-sandbox' instead.`)
    );
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

  if (runner.buildImage(options.path)) {
    console.log(bold(green('✔ Successfully built sandbox Docker image: security-audit-sandbox:latest\n')));
  } else {
    console.error(red('\n✖ Local Docker build failed.'));
    process.exit(1);
  }
}
