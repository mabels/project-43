import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';

// Integration tests will be added once the key-store test fixture is wired up.
void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();
  testWidgets('smoke test placeholder', (tester) async {
    expect(true, isTrue);
  });
}
