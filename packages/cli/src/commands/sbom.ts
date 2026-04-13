/**
 * `safedeps sbom`
 *
 * Generates a CycloneDX 1.5 JSON Software Bill of Materials (SBOM) for the
 * current project's npm dependencies.
 *
 * Usage:
 *   safedeps sbom                          # stdout
 *   safedeps sbom --output sbom.json       # write to file
 *   safedeps sbom --include-dev            # include devDependencies
 *   safedeps sbom --path /other/project    # specify project root
 */

import fs from 'fs';
import path from 'path';
import { Command } from 'commander';
import { parsePackageJson } from '../utils/packageParser';
import { parseLockfile, parseLockfileIntegrity } from '../utils/lockfileParser';
import { generateCycloneDxBom } from '../generators/cyclonedx';
import pkg from '../../package.json';

interface SbomOptions {
  path:       string;
  output?:    string;
  includeDev: boolean;
}

export default function registerSbomCommand(program: Command): void {
  program
    .command('sbom')
    .description('Generate a CycloneDX 1.5 SBOM for the project\'s npm dependencies')
    .option('-p, --path <dir>',      'Project root directory',  process.cwd())
    .option('-o, --output <file>',   'Write SBOM to file instead of stdout')
    .option('--include-dev',         'Include devDependencies in the SBOM', false)
    .action(async (opts: SbomOptions) => {
      const projectPath = path.resolve(opts.path);

      let parsedPkg: ReturnType<typeof parsePackageJson>;
      try {
        parsedPkg = parsePackageJson(projectPath);
      } catch (err) {
        console.error(`Error reading package.json: ${(err as Error).message}`);
        process.exit(1);
      }

      const lockVersions  = parseLockfile(projectPath);
      const integrityMap  = parseLockfileIntegrity(projectPath);

      // Read licenses from node_modules (best-effort)
      const packageMeta = new Map<string, { license: string | null; integrity?: string }>();
      const allNames = [
        ...Object.keys(parsedPkg.dependencies),
        ...(opts.includeDev ? Object.keys(parsedPkg.devDependencies) : []),
      ];

      for (const name of allNames) {
        try {
          const pkgJsonPath = path.join(projectPath, 'node_modules', name, 'package.json');
          if (fs.existsSync(pkgJsonPath)) {
            const raw = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf8')) as Record<string, unknown>;
            const license = typeof raw.license === 'string' ? raw.license : null;
            packageMeta.set(name, { license });
          }
        } catch {
          // Silently skip — packageMeta entry will be absent; BOM omits license for this pkg
        }
      }

      const bom = generateCycloneDxBom(parsedPkg, lockVersions, {
        packageMeta,
        integrityMap,
        includeDev:     opts.includeDev,
        projectName:    parsedPkg.name,
        projectVersion: parsedPkg.version,
        toolVersion:    pkg.version,
      });

      const output = JSON.stringify(bom, null, 2);

      if (opts.output) {
        const outPath = path.resolve(opts.output);
        fs.writeFileSync(outPath, output, 'utf8');
        console.error(`SBOM written to ${outPath}`);
      } else {
        process.stdout.write(output + '\n');
      }
    });
}
