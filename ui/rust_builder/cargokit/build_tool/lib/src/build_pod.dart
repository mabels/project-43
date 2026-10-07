/// This is copied from Cargokit (which is the official way to use it currently)
/// Details: https://fzyzcjy.github.io/flutter_rust_bridge/manual/integrate/builtin

import 'dart:io';

import 'package:path/path.dart' as path;

import 'artifacts_provider.dart';
import 'builder.dart';
import 'environment.dart';
import 'options.dart';
import 'target.dart';
import 'util.dart';

class BuildPod {
  BuildPod({required this.userOptions});

  final CargokitUserOptions userOptions;

  Future<void> build() async {
    final targets = Environment.darwinArchs.map((arch) {
      final target = Target.forDarwin(
          platformName: Environment.darwinPlatformName, darwinAarch: arch);
      if (target == null) {
        throw Exception(
            "Unknown darwin target or platform: $arch, ${Environment.darwinPlatformName}");
      }
      return target;
    }).toList();

    final environment = BuildEnvironment.fromEnvironment(isAndroid: false);
    final provider =
        ArtifactProvider(environment: environment, userOptions: userOptions);
    final artifacts = await provider.getArtifacts(targets);

    void performLipo(String targetFile, Iterable<String> sourceFiles) {
      // `lipo -create` creates the output with O_EXCL when it does not exist
      // yet, so it fails with `errno=17 (File exists)` when the build script
      // phase runs more than once concurrently for the same output (Xcode can
      // schedule it that way, e.g. for multiple targets/slices). Write to a
      // unique temporary file first and atomically rename it into place so
      // concurrent invocations cannot collide.
      final tempFile =
          '$targetFile.tmp-$pid-${DateTime.now().microsecondsSinceEpoch}';
      try {
        runCommand("lipo", [
          '-create',
          ...sourceFiles,
          '-output',
          tempFile,
        ]);
        File(tempFile).renameSync(targetFile);
      } finally {
        final leftover = File(tempFile);
        if (leftover.existsSync()) {
          leftover.deleteSync();
        }
      }
    }

    final outputDir = Environment.outputDir;

    Directory(outputDir).createSync(recursive: true);

    final staticLibs = artifacts.values
        .expand((element) => element)
        .where((element) => element.type == AritifactType.staticlib)
        .toList();
    final dynamicLibs = artifacts.values
        .expand((element) => element)
        .where((element) => element.type == AritifactType.dylib)
        .toList();

    final libName = environment.crateInfo.packageName;

    // If there is static lib, use it and link it with pod
    if (staticLibs.isNotEmpty) {
      final finalTargetFile = path.join(outputDir, "lib$libName.a");
      performLipo(finalTargetFile, staticLibs.map((e) => e.path));
    } else {
      // Otherwise try to replace bundle dylib with our dylib
      final bundlePaths = [
        '$libName.framework/Versions/A/$libName',
        '$libName.framework/$libName',
      ];

      for (final bundlePath in bundlePaths) {
        final targetFile = path.join(outputDir, bundlePath);
        if (File(targetFile).existsSync()) {
          performLipo(targetFile, dynamicLibs.map((e) => e.path));

          // Replace absolute id with @rpath one so that it works properly
          // when moved to Frameworks.
          runCommand("install_name_tool", [
            '-id',
            '@rpath/$bundlePath',
            targetFile,
          ]);
          return;
        }
      }
      throw Exception('Unable to find bundle for dynamic library');
    }
  }
}
