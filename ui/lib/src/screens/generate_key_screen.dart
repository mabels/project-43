import 'package:flutter/material.dart';
import 'package:p43/src/rust/api/simple.dart';

const _algos = ['ed25519', 'rsa4096', 'rsa3072'];

class GenerateKeyScreen extends StatefulWidget {
  const GenerateKeyScreen({super.key});

  @override
  State<GenerateKeyScreen> createState() => _GenerateKeyScreenState();
}

class _GenerateKeyScreenState extends State<GenerateKeyScreen> {
  final _formKey = GlobalKey<FormState>();
  final _nameCtrl = TextEditingController();
  final _emailCtrl = TextEditingController();
  final _passphraseCtrl = TextEditingController();
  final _confirmCtrl = TextEditingController();

  String _algo = 'ed25519';
  bool _busy = false;
  String? _error;

  @override
  void dispose() {
    _nameCtrl.dispose();
    _emailCtrl.dispose();
    _passphraseCtrl.dispose();
    _confirmCtrl.dispose();
    super.dispose();
  }

  Future<void> _submit() async {
    if (!_formKey.currentState!.validate()) return;

    final passphrase = _passphraseCtrl.text.trim();
    final uid = '${_nameCtrl.text.trim()} <${_emailCtrl.text.trim()}>';

    setState(() {
      _busy = true;
      _error = null;
    });

    try {
      await generateKey(
        uid: uid,
        algo: _algo,
        passphrase: passphrase.isEmpty ? null : passphrase,
      );
      if (mounted) Navigator.pop(context, true);
    } catch (e) {
      setState(() {
        _error = e.toString();
        _busy = false;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    final showConfirm = _passphraseCtrl.text.isNotEmpty;

    return Scaffold(
      appBar: AppBar(
        backgroundColor: const Color(0xFF1C1C1E),
        title: const Text(
          'Generate Key',
          style: TextStyle(fontSize: 17, fontWeight: FontWeight.w600),
        ),
      ),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(20),
        child: Form(
          key: _formKey,
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              _Field(
                label: 'Name',
                controller: _nameCtrl,
                placeholder: 'Alice',
                enabled: !_busy,
                autofocus: true,
                validator: (v) =>
                    (v == null || v.trim().isEmpty) ? 'Name is required' : null,
              ),
              const SizedBox(height: 12),
              _Field(
                label: 'Email',
                controller: _emailCtrl,
                placeholder: 'alice@example.com',
                keyboardType: TextInputType.emailAddress,
                enabled: !_busy,
                validator: (v) {
                  if (v == null || v.trim().isEmpty) return 'Email is required';
                  if (!RegExp(r'^[^\s@]+@[^\s@]+\.[^\s@]+$').hasMatch(v.trim())) {
                    return 'Enter a valid email address';
                  }
                  return null;
                },
              ),
              const SizedBox(height: 12),
              _DropdownField(
                label: 'Algorithm',
                value: _algo,
                items: _algos,
                enabled: !_busy,
                onChanged: (v) => setState(() => _algo = v!),
              ),
              const SizedBox(height: 12),
              _Field(
                label: 'Passphrase',
                hint: 'optional',
                controller: _passphraseCtrl,
                placeholder: 'Leave empty for no encryption',
                obscure: true,
                enabled: !_busy,
                onChanged: (_) => setState(() {}),
              ),
              if (showConfirm) ...[
                const SizedBox(height: 12),
                _Field(
                  label: 'Confirm Passphrase',
                  controller: _confirmCtrl,
                  placeholder: 'Repeat passphrase',
                  obscure: true,
                  enabled: !_busy,
                  validator: (v) => v != _passphraseCtrl.text
                      ? 'Passphrases do not match'
                      : null,
                ),
              ],
              if (_error != null) ...[
                const SizedBox(height: 14),
                Text(
                  _error!,
                  style: const TextStyle(
                    color: Color(0xFFFF453A),
                    fontSize: 13,
                  ),
                ),
              ],
              const SizedBox(height: 24),
              FilledButton(
                onPressed: _busy ? null : _submit,
                style: FilledButton.styleFrom(
                  backgroundColor: const Color(0xFF0A84FF),
                  padding: const EdgeInsets.symmetric(vertical: 14),
                  shape: RoundedRectangleBorder(
                    borderRadius: BorderRadius.circular(10),
                  ),
                ),
                child: _busy
                    ? const SizedBox(
                        height: 18,
                        width: 18,
                        child: CircularProgressIndicator(
                          strokeWidth: 2,
                          color: Colors.white,
                        ),
                      )
                    : const Text(
                        'Generate',
                        style: TextStyle(
                          fontSize: 15,
                          fontWeight: FontWeight.w600,
                        ),
                      ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

// ── Shared form widgets ───────────────────────────────────────────────────────

class _Field extends StatelessWidget {
  const _Field({
    required this.label,
    required this.controller,
    required this.placeholder,
    this.hint,
    this.obscure = false,
    this.enabled = true,
    this.autofocus = false,
    this.keyboardType,
    this.validator,
    this.onChanged,
  });

  final String label;
  final String? hint;
  final TextEditingController controller;
  final String placeholder;
  final bool obscure;
  final bool enabled;
  final bool autofocus;
  final TextInputType? keyboardType;
  final String? Function(String?)? validator;
  final void Function(String)? onChanged;

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          children: [
            Text(
              label,
              style: const TextStyle(
                fontSize: 12,
                fontWeight: FontWeight.w500,
                color: Color(0xFF8E8E93),
              ),
            ),
            if (hint != null) ...[
              const SizedBox(width: 4),
              Text(
                '($hint)',
                style: const TextStyle(
                  fontSize: 11,
                  color: Color(0xFF636366),
                ),
              ),
            ],
          ],
        ),
        const SizedBox(height: 4),
        TextFormField(
          controller: controller,
          obscureText: obscure,
          enabled: enabled,
          autofocus: autofocus,
          keyboardType: keyboardType,
          onChanged: onChanged,
          validator: validator,
          style: const TextStyle(fontSize: 14),
          decoration: InputDecoration(
            hintText: placeholder,
            hintStyle: const TextStyle(color: Color(0xFF636366), fontSize: 13),
            filled: true,
            fillColor: const Color(0xFF1A1A1C),
            border: OutlineInputBorder(
              borderRadius: BorderRadius.circular(8),
              borderSide: const BorderSide(color: Color(0xFF3A3A3C)),
            ),
            enabledBorder: OutlineInputBorder(
              borderRadius: BorderRadius.circular(8),
              borderSide: const BorderSide(color: Color(0xFF3A3A3C)),
            ),
            focusedBorder: OutlineInputBorder(
              borderRadius: BorderRadius.circular(8),
              borderSide: const BorderSide(color: Color(0xFF0A84FF)),
            ),
            errorBorder: OutlineInputBorder(
              borderRadius: BorderRadius.circular(8),
              borderSide: const BorderSide(color: Color(0xFFFF453A)),
            ),
            contentPadding:
                const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
          ),
        ),
      ],
    );
  }
}

class _DropdownField extends StatelessWidget {
  const _DropdownField({
    required this.label,
    required this.value,
    required this.items,
    required this.onChanged,
    this.enabled = true,
  });

  final String label;
  final String value;
  final List<String> items;
  final void Function(String?) onChanged;
  final bool enabled;

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          label,
          style: const TextStyle(
            fontSize: 12,
            fontWeight: FontWeight.w500,
            color: Color(0xFF8E8E93),
          ),
        ),
        const SizedBox(height: 4),
        DropdownButtonFormField<String>(
          initialValue: value,
          onChanged: enabled ? onChanged : null,
          dropdownColor: const Color(0xFF2C2C2E),
          style: const TextStyle(fontSize: 14, color: Colors.white),
          decoration: InputDecoration(
            filled: true,
            fillColor: const Color(0xFF1A1A1C),
            border: OutlineInputBorder(
              borderRadius: BorderRadius.circular(8),
              borderSide: const BorderSide(color: Color(0xFF3A3A3C)),
            ),
            enabledBorder: OutlineInputBorder(
              borderRadius: BorderRadius.circular(8),
              borderSide: const BorderSide(color: Color(0xFF3A3A3C)),
            ),
            focusedBorder: OutlineInputBorder(
              borderRadius: BorderRadius.circular(8),
              borderSide: const BorderSide(color: Color(0xFF0A84FF)),
            ),
            contentPadding:
                const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
          ),
          items: items
              .map((a) => DropdownMenuItem(value: a, child: Text(a)))
              .toList(),
        ),
      ],
    );
  }
}
