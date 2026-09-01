#!/usr/bin/env node

import { createCli } from '../dist/src/cli/index.js';

const program = createCli();
program.parse(process.argv);
