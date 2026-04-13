#!/usr/bin/env node

import { program } from 'commander';
import pkg from '../package.json';
import registerScanCommand from '../src/commands/scan';
import registerCheckCommand from '../src/commands/check';
import registerUpdatePackagesCommand from '../src/commands/updatePackages';
import registerDiffCommand from '../src/commands/diff';
import registerGuardCommand from '../src/commands/guard';
import registerSbomCommand from '../src/commands/sbom';

program
  .name('safedeps')
  .description('Open source npm package security scanner')
  .version(pkg.version);

// Register commands
registerScanCommand(program);
registerCheckCommand(program);
registerUpdatePackagesCommand(program);
registerDiffCommand(program);
registerGuardCommand(program);
registerSbomCommand(program);

program.parse(process.argv);

// Show help if no command provided
if (!process.argv.slice(2).length) {
  program.outputHelp();
}
