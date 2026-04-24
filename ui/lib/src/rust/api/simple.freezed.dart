// coverage:ignore-file
// GENERATED CODE - DO NOT MODIFY BY HAND
// ignore_for_file: type=lint
// ignore_for_file: unused_element, deprecated_member_use, deprecated_member_use_from_same_package, use_function_type_syntax_for_parameters, unnecessary_const, avoid_init_to_null, invalid_override_different_default_values_named, prefer_expression_function_bodies, annotate_overrides, invalid_annotation_target, unnecessary_question_mark

part of 'simple.dart';

// **************************************************************************
// FreezedGenerator
// **************************************************************************

T _$identity<T>(T value) => value;

final _privateConstructorUsedError = UnsupportedError(
  'It seems like you constructed your class using `MyClass._()`. This constructor is only meant to be used by freezed and you are not supposed to need it nor use it.\nPlease check the documentation here for more information: https://github.com/rrousselGit/freezed#adding-getters-and-methods-to-our-models',
);

/// @nodoc
mixin _$AgentRequest {
  String get requestId => throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function(String requestId) listKeys,
    required TResult Function(
      String requestId,
      String fingerprint,
      String description,
      String deviceLabel,
      String deviceId,
    )
    sign,
  }) => throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function(String requestId)? listKeys,
    TResult? Function(
      String requestId,
      String fingerprint,
      String description,
      String deviceLabel,
      String deviceId,
    )?
    sign,
  }) => throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function(String requestId)? listKeys,
    TResult Function(
      String requestId,
      String fingerprint,
      String description,
      String deviceLabel,
      String deviceId,
    )?
    sign,
    required TResult orElse(),
  }) => throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(AgentRequest_ListKeys value) listKeys,
    required TResult Function(AgentRequest_Sign value) sign,
  }) => throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(AgentRequest_ListKeys value)? listKeys,
    TResult? Function(AgentRequest_Sign value)? sign,
  }) => throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(AgentRequest_ListKeys value)? listKeys,
    TResult Function(AgentRequest_Sign value)? sign,
    required TResult orElse(),
  }) => throw _privateConstructorUsedError;

  /// Create a copy of AgentRequest
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  $AgentRequestCopyWith<AgentRequest> get copyWith =>
      throw _privateConstructorUsedError;
}

/// @nodoc
abstract class $AgentRequestCopyWith<$Res> {
  factory $AgentRequestCopyWith(
    AgentRequest value,
    $Res Function(AgentRequest) then,
  ) = _$AgentRequestCopyWithImpl<$Res, AgentRequest>;
  @useResult
  $Res call({String requestId});
}

/// @nodoc
class _$AgentRequestCopyWithImpl<$Res, $Val extends AgentRequest>
    implements $AgentRequestCopyWith<$Res> {
  _$AgentRequestCopyWithImpl(this._value, this._then);

  // ignore: unused_field
  final $Val _value;
  // ignore: unused_field
  final $Res Function($Val) _then;

  /// Create a copy of AgentRequest
  /// with the given fields replaced by the non-null parameter values.
  @pragma('vm:prefer-inline')
  @override
  $Res call({Object? requestId = null}) {
    return _then(
      _value.copyWith(
            requestId: null == requestId
                ? _value.requestId
                : requestId // ignore: cast_nullable_to_non_nullable
                      as String,
          )
          as $Val,
    );
  }
}

/// @nodoc
abstract class _$$AgentRequest_ListKeysImplCopyWith<$Res>
    implements $AgentRequestCopyWith<$Res> {
  factory _$$AgentRequest_ListKeysImplCopyWith(
    _$AgentRequest_ListKeysImpl value,
    $Res Function(_$AgentRequest_ListKeysImpl) then,
  ) = __$$AgentRequest_ListKeysImplCopyWithImpl<$Res>;
  @override
  @useResult
  $Res call({String requestId});
}

/// @nodoc
class __$$AgentRequest_ListKeysImplCopyWithImpl<$Res>
    extends _$AgentRequestCopyWithImpl<$Res, _$AgentRequest_ListKeysImpl>
    implements _$$AgentRequest_ListKeysImplCopyWith<$Res> {
  __$$AgentRequest_ListKeysImplCopyWithImpl(
    _$AgentRequest_ListKeysImpl _value,
    $Res Function(_$AgentRequest_ListKeysImpl) _then,
  ) : super(_value, _then);

  /// Create a copy of AgentRequest
  /// with the given fields replaced by the non-null parameter values.
  @pragma('vm:prefer-inline')
  @override
  $Res call({Object? requestId = null}) {
    return _then(
      _$AgentRequest_ListKeysImpl(
        requestId: null == requestId
            ? _value.requestId
            : requestId // ignore: cast_nullable_to_non_nullable
                  as String,
      ),
    );
  }
}

/// @nodoc

class _$AgentRequest_ListKeysImpl extends AgentRequest_ListKeys {
  const _$AgentRequest_ListKeysImpl({required this.requestId}) : super._();

  @override
  final String requestId;

  @override
  String toString() {
    return 'AgentRequest.listKeys(requestId: $requestId)';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$AgentRequest_ListKeysImpl &&
            (identical(other.requestId, requestId) ||
                other.requestId == requestId));
  }

  @override
  int get hashCode => Object.hash(runtimeType, requestId);

  /// Create a copy of AgentRequest
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  @override
  @pragma('vm:prefer-inline')
  _$$AgentRequest_ListKeysImplCopyWith<_$AgentRequest_ListKeysImpl>
  get copyWith =>
      __$$AgentRequest_ListKeysImplCopyWithImpl<_$AgentRequest_ListKeysImpl>(
        this,
        _$identity,
      );

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function(String requestId) listKeys,
    required TResult Function(
      String requestId,
      String fingerprint,
      String description,
      String deviceLabel,
      String deviceId,
    )
    sign,
  }) {
    return listKeys(requestId);
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function(String requestId)? listKeys,
    TResult? Function(
      String requestId,
      String fingerprint,
      String description,
      String deviceLabel,
      String deviceId,
    )?
    sign,
  }) {
    return listKeys?.call(requestId);
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function(String requestId)? listKeys,
    TResult Function(
      String requestId,
      String fingerprint,
      String description,
      String deviceLabel,
      String deviceId,
    )?
    sign,
    required TResult orElse(),
  }) {
    if (listKeys != null) {
      return listKeys(requestId);
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(AgentRequest_ListKeys value) listKeys,
    required TResult Function(AgentRequest_Sign value) sign,
  }) {
    return listKeys(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(AgentRequest_ListKeys value)? listKeys,
    TResult? Function(AgentRequest_Sign value)? sign,
  }) {
    return listKeys?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(AgentRequest_ListKeys value)? listKeys,
    TResult Function(AgentRequest_Sign value)? sign,
    required TResult orElse(),
  }) {
    if (listKeys != null) {
      return listKeys(this);
    }
    return orElse();
  }
}

abstract class AgentRequest_ListKeys extends AgentRequest {
  const factory AgentRequest_ListKeys({required final String requestId}) =
      _$AgentRequest_ListKeysImpl;
  const AgentRequest_ListKeys._() : super._();

  @override
  String get requestId;

  /// Create a copy of AgentRequest
  /// with the given fields replaced by the non-null parameter values.
  @override
  @JsonKey(includeFromJson: false, includeToJson: false)
  _$$AgentRequest_ListKeysImplCopyWith<_$AgentRequest_ListKeysImpl>
  get copyWith => throw _privateConstructorUsedError;
}

/// @nodoc
abstract class _$$AgentRequest_SignImplCopyWith<$Res>
    implements $AgentRequestCopyWith<$Res> {
  factory _$$AgentRequest_SignImplCopyWith(
    _$AgentRequest_SignImpl value,
    $Res Function(_$AgentRequest_SignImpl) then,
  ) = __$$AgentRequest_SignImplCopyWithImpl<$Res>;
  @override
  @useResult
  $Res call({
    String requestId,
    String fingerprint,
    String description,
    String deviceLabel,
    String deviceId,
  });
}

/// @nodoc
class __$$AgentRequest_SignImplCopyWithImpl<$Res>
    extends _$AgentRequestCopyWithImpl<$Res, _$AgentRequest_SignImpl>
    implements _$$AgentRequest_SignImplCopyWith<$Res> {
  __$$AgentRequest_SignImplCopyWithImpl(
    _$AgentRequest_SignImpl _value,
    $Res Function(_$AgentRequest_SignImpl) _then,
  ) : super(_value, _then);

  /// Create a copy of AgentRequest
  /// with the given fields replaced by the non-null parameter values.
  @pragma('vm:prefer-inline')
  @override
  $Res call({
    Object? requestId = null,
    Object? fingerprint = null,
    Object? description = null,
    Object? deviceLabel = null,
    Object? deviceId = null,
  }) {
    return _then(
      _$AgentRequest_SignImpl(
        requestId: null == requestId
            ? _value.requestId
            : requestId // ignore: cast_nullable_to_non_nullable
                  as String,
        fingerprint: null == fingerprint
            ? _value.fingerprint
            : fingerprint // ignore: cast_nullable_to_non_nullable
                  as String,
        description: null == description
            ? _value.description
            : description // ignore: cast_nullable_to_non_nullable
                  as String,
        deviceLabel: null == deviceLabel
            ? _value.deviceLabel
            : deviceLabel // ignore: cast_nullable_to_non_nullable
                  as String,
        deviceId: null == deviceId
            ? _value.deviceId
            : deviceId // ignore: cast_nullable_to_non_nullable
                  as String,
      ),
    );
  }
}

/// @nodoc

class _$AgentRequest_SignImpl extends AgentRequest_Sign {
  const _$AgentRequest_SignImpl({
    required this.requestId,
    required this.fingerprint,
    required this.description,
    required this.deviceLabel,
    required this.deviceId,
  }) : super._();

  @override
  final String requestId;
  @override
  final String fingerprint;
  @override
  final String description;

  /// Label from the sender's bus certificate (empty if unauthenticated).
  @override
  final String deviceLabel;

  /// Stable device identifier from the sender's bus certificate (empty if unauthenticated).
  @override
  final String deviceId;

  @override
  String toString() {
    return 'AgentRequest.sign(requestId: $requestId, fingerprint: $fingerprint, description: $description, deviceLabel: $deviceLabel, deviceId: $deviceId)';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$AgentRequest_SignImpl &&
            (identical(other.requestId, requestId) ||
                other.requestId == requestId) &&
            (identical(other.fingerprint, fingerprint) ||
                other.fingerprint == fingerprint) &&
            (identical(other.description, description) ||
                other.description == description) &&
            (identical(other.deviceLabel, deviceLabel) ||
                other.deviceLabel == deviceLabel) &&
            (identical(other.deviceId, deviceId) ||
                other.deviceId == deviceId));
  }

  @override
  int get hashCode => Object.hash(
    runtimeType,
    requestId,
    fingerprint,
    description,
    deviceLabel,
    deviceId,
  );

  /// Create a copy of AgentRequest
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  @override
  @pragma('vm:prefer-inline')
  _$$AgentRequest_SignImplCopyWith<_$AgentRequest_SignImpl> get copyWith =>
      __$$AgentRequest_SignImplCopyWithImpl<_$AgentRequest_SignImpl>(
        this,
        _$identity,
      );

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function(String requestId) listKeys,
    required TResult Function(
      String requestId,
      String fingerprint,
      String description,
      String deviceLabel,
      String deviceId,
    )
    sign,
  }) {
    return sign(requestId, fingerprint, description, deviceLabel, deviceId);
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function(String requestId)? listKeys,
    TResult? Function(
      String requestId,
      String fingerprint,
      String description,
      String deviceLabel,
      String deviceId,
    )?
    sign,
  }) {
    return sign?.call(
      requestId,
      fingerprint,
      description,
      deviceLabel,
      deviceId,
    );
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function(String requestId)? listKeys,
    TResult Function(
      String requestId,
      String fingerprint,
      String description,
      String deviceLabel,
      String deviceId,
    )?
    sign,
    required TResult orElse(),
  }) {
    if (sign != null) {
      return sign(requestId, fingerprint, description, deviceLabel, deviceId);
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(AgentRequest_ListKeys value) listKeys,
    required TResult Function(AgentRequest_Sign value) sign,
  }) {
    return sign(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(AgentRequest_ListKeys value)? listKeys,
    TResult? Function(AgentRequest_Sign value)? sign,
  }) {
    return sign?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(AgentRequest_ListKeys value)? listKeys,
    TResult Function(AgentRequest_Sign value)? sign,
    required TResult orElse(),
  }) {
    if (sign != null) {
      return sign(this);
    }
    return orElse();
  }
}

abstract class AgentRequest_Sign extends AgentRequest {
  const factory AgentRequest_Sign({
    required final String requestId,
    required final String fingerprint,
    required final String description,
    required final String deviceLabel,
    required final String deviceId,
  }) = _$AgentRequest_SignImpl;
  const AgentRequest_Sign._() : super._();

  @override
  String get requestId;
  String get fingerprint;
  String get description;

  /// Label from the sender's bus certificate (empty if unauthenticated).
  String get deviceLabel;

  /// Stable device identifier from the sender's bus certificate (empty if unauthenticated).
  String get deviceId;

  /// Create a copy of AgentRequest
  /// with the given fields replaced by the non-null parameter values.
  @override
  @JsonKey(includeFromJson: false, includeToJson: false)
  _$$AgentRequest_SignImplCopyWith<_$AgentRequest_SignImpl> get copyWith =>
      throw _privateConstructorUsedError;
}

/// @nodoc
mixin _$AppMessage {
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function(AgentRequest event) agentEvent,
    required TResult Function(BusCsrEvent event) busEvent,
    required TResult Function() sessionLockRequired,
  }) => throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function(AgentRequest event)? agentEvent,
    TResult? Function(BusCsrEvent event)? busEvent,
    TResult? Function()? sessionLockRequired,
  }) => throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function(AgentRequest event)? agentEvent,
    TResult Function(BusCsrEvent event)? busEvent,
    TResult Function()? sessionLockRequired,
    required TResult orElse(),
  }) => throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(AppMessage_AgentEvent value) agentEvent,
    required TResult Function(AppMessage_BusEvent value) busEvent,
    required TResult Function(AppMessage_SessionLockRequired value)
    sessionLockRequired,
  }) => throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(AppMessage_AgentEvent value)? agentEvent,
    TResult? Function(AppMessage_BusEvent value)? busEvent,
    TResult? Function(AppMessage_SessionLockRequired value)?
    sessionLockRequired,
  }) => throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(AppMessage_AgentEvent value)? agentEvent,
    TResult Function(AppMessage_BusEvent value)? busEvent,
    TResult Function(AppMessage_SessionLockRequired value)? sessionLockRequired,
    required TResult orElse(),
  }) => throw _privateConstructorUsedError;
}

/// @nodoc
abstract class $AppMessageCopyWith<$Res> {
  factory $AppMessageCopyWith(
    AppMessage value,
    $Res Function(AppMessage) then,
  ) = _$AppMessageCopyWithImpl<$Res, AppMessage>;
}

/// @nodoc
class _$AppMessageCopyWithImpl<$Res, $Val extends AppMessage>
    implements $AppMessageCopyWith<$Res> {
  _$AppMessageCopyWithImpl(this._value, this._then);

  // ignore: unused_field
  final $Val _value;
  // ignore: unused_field
  final $Res Function($Val) _then;

  /// Create a copy of AppMessage
  /// with the given fields replaced by the non-null parameter values.
}

/// @nodoc
abstract class _$$AppMessage_AgentEventImplCopyWith<$Res> {
  factory _$$AppMessage_AgentEventImplCopyWith(
    _$AppMessage_AgentEventImpl value,
    $Res Function(_$AppMessage_AgentEventImpl) then,
  ) = __$$AppMessage_AgentEventImplCopyWithImpl<$Res>;
  @useResult
  $Res call({AgentRequest event});

  $AgentRequestCopyWith<$Res> get event;
}

/// @nodoc
class __$$AppMessage_AgentEventImplCopyWithImpl<$Res>
    extends _$AppMessageCopyWithImpl<$Res, _$AppMessage_AgentEventImpl>
    implements _$$AppMessage_AgentEventImplCopyWith<$Res> {
  __$$AppMessage_AgentEventImplCopyWithImpl(
    _$AppMessage_AgentEventImpl _value,
    $Res Function(_$AppMessage_AgentEventImpl) _then,
  ) : super(_value, _then);

  /// Create a copy of AppMessage
  /// with the given fields replaced by the non-null parameter values.
  @pragma('vm:prefer-inline')
  @override
  $Res call({Object? event = null}) {
    return _then(
      _$AppMessage_AgentEventImpl(
        event: null == event
            ? _value.event
            : event // ignore: cast_nullable_to_non_nullable
                  as AgentRequest,
      ),
    );
  }

  /// Create a copy of AppMessage
  /// with the given fields replaced by the non-null parameter values.
  @override
  @pragma('vm:prefer-inline')
  $AgentRequestCopyWith<$Res> get event {
    return $AgentRequestCopyWith<$Res>(_value.event, (value) {
      return _then(_value.copyWith(event: value));
    });
  }
}

/// @nodoc

class _$AppMessage_AgentEventImpl extends AppMessage_AgentEvent {
  const _$AppMessage_AgentEventImpl({required this.event}) : super._();

  @override
  final AgentRequest event;

  @override
  String toString() {
    return 'AppMessage.agentEvent(event: $event)';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$AppMessage_AgentEventImpl &&
            (identical(other.event, event) || other.event == event));
  }

  @override
  int get hashCode => Object.hash(runtimeType, event);

  /// Create a copy of AppMessage
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  @override
  @pragma('vm:prefer-inline')
  _$$AppMessage_AgentEventImplCopyWith<_$AppMessage_AgentEventImpl>
  get copyWith =>
      __$$AppMessage_AgentEventImplCopyWithImpl<_$AppMessage_AgentEventImpl>(
        this,
        _$identity,
      );

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function(AgentRequest event) agentEvent,
    required TResult Function(BusCsrEvent event) busEvent,
    required TResult Function() sessionLockRequired,
  }) {
    return agentEvent(event);
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function(AgentRequest event)? agentEvent,
    TResult? Function(BusCsrEvent event)? busEvent,
    TResult? Function()? sessionLockRequired,
  }) {
    return agentEvent?.call(event);
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function(AgentRequest event)? agentEvent,
    TResult Function(BusCsrEvent event)? busEvent,
    TResult Function()? sessionLockRequired,
    required TResult orElse(),
  }) {
    if (agentEvent != null) {
      return agentEvent(event);
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(AppMessage_AgentEvent value) agentEvent,
    required TResult Function(AppMessage_BusEvent value) busEvent,
    required TResult Function(AppMessage_SessionLockRequired value)
    sessionLockRequired,
  }) {
    return agentEvent(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(AppMessage_AgentEvent value)? agentEvent,
    TResult? Function(AppMessage_BusEvent value)? busEvent,
    TResult? Function(AppMessage_SessionLockRequired value)?
    sessionLockRequired,
  }) {
    return agentEvent?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(AppMessage_AgentEvent value)? agentEvent,
    TResult Function(AppMessage_BusEvent value)? busEvent,
    TResult Function(AppMessage_SessionLockRequired value)? sessionLockRequired,
    required TResult orElse(),
  }) {
    if (agentEvent != null) {
      return agentEvent(this);
    }
    return orElse();
  }
}

abstract class AppMessage_AgentEvent extends AppMessage {
  const factory AppMessage_AgentEvent({required final AgentRequest event}) =
      _$AppMessage_AgentEventImpl;
  const AppMessage_AgentEvent._() : super._();

  AgentRequest get event;

  /// Create a copy of AppMessage
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  _$$AppMessage_AgentEventImplCopyWith<_$AppMessage_AgentEventImpl>
  get copyWith => throw _privateConstructorUsedError;
}

/// @nodoc
abstract class _$$AppMessage_BusEventImplCopyWith<$Res> {
  factory _$$AppMessage_BusEventImplCopyWith(
    _$AppMessage_BusEventImpl value,
    $Res Function(_$AppMessage_BusEventImpl) then,
  ) = __$$AppMessage_BusEventImplCopyWithImpl<$Res>;
  @useResult
  $Res call({BusCsrEvent event});
}

/// @nodoc
class __$$AppMessage_BusEventImplCopyWithImpl<$Res>
    extends _$AppMessageCopyWithImpl<$Res, _$AppMessage_BusEventImpl>
    implements _$$AppMessage_BusEventImplCopyWith<$Res> {
  __$$AppMessage_BusEventImplCopyWithImpl(
    _$AppMessage_BusEventImpl _value,
    $Res Function(_$AppMessage_BusEventImpl) _then,
  ) : super(_value, _then);

  /// Create a copy of AppMessage
  /// with the given fields replaced by the non-null parameter values.
  @pragma('vm:prefer-inline')
  @override
  $Res call({Object? event = null}) {
    return _then(
      _$AppMessage_BusEventImpl(
        event: null == event
            ? _value.event
            : event // ignore: cast_nullable_to_non_nullable
                  as BusCsrEvent,
      ),
    );
  }
}

/// @nodoc

class _$AppMessage_BusEventImpl extends AppMessage_BusEvent {
  const _$AppMessage_BusEventImpl({required this.event}) : super._();

  @override
  final BusCsrEvent event;

  @override
  String toString() {
    return 'AppMessage.busEvent(event: $event)';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$AppMessage_BusEventImpl &&
            (identical(other.event, event) || other.event == event));
  }

  @override
  int get hashCode => Object.hash(runtimeType, event);

  /// Create a copy of AppMessage
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  @override
  @pragma('vm:prefer-inline')
  _$$AppMessage_BusEventImplCopyWith<_$AppMessage_BusEventImpl> get copyWith =>
      __$$AppMessage_BusEventImplCopyWithImpl<_$AppMessage_BusEventImpl>(
        this,
        _$identity,
      );

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function(AgentRequest event) agentEvent,
    required TResult Function(BusCsrEvent event) busEvent,
    required TResult Function() sessionLockRequired,
  }) {
    return busEvent(event);
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function(AgentRequest event)? agentEvent,
    TResult? Function(BusCsrEvent event)? busEvent,
    TResult? Function()? sessionLockRequired,
  }) {
    return busEvent?.call(event);
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function(AgentRequest event)? agentEvent,
    TResult Function(BusCsrEvent event)? busEvent,
    TResult Function()? sessionLockRequired,
    required TResult orElse(),
  }) {
    if (busEvent != null) {
      return busEvent(event);
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(AppMessage_AgentEvent value) agentEvent,
    required TResult Function(AppMessage_BusEvent value) busEvent,
    required TResult Function(AppMessage_SessionLockRequired value)
    sessionLockRequired,
  }) {
    return busEvent(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(AppMessage_AgentEvent value)? agentEvent,
    TResult? Function(AppMessage_BusEvent value)? busEvent,
    TResult? Function(AppMessage_SessionLockRequired value)?
    sessionLockRequired,
  }) {
    return busEvent?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(AppMessage_AgentEvent value)? agentEvent,
    TResult Function(AppMessage_BusEvent value)? busEvent,
    TResult Function(AppMessage_SessionLockRequired value)? sessionLockRequired,
    required TResult orElse(),
  }) {
    if (busEvent != null) {
      return busEvent(this);
    }
    return orElse();
  }
}

abstract class AppMessage_BusEvent extends AppMessage {
  const factory AppMessage_BusEvent({required final BusCsrEvent event}) =
      _$AppMessage_BusEventImpl;
  const AppMessage_BusEvent._() : super._();

  BusCsrEvent get event;

  /// Create a copy of AppMessage
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  _$$AppMessage_BusEventImplCopyWith<_$AppMessage_BusEventImpl> get copyWith =>
      throw _privateConstructorUsedError;
}

/// @nodoc
abstract class _$$AppMessage_SessionLockRequiredImplCopyWith<$Res> {
  factory _$$AppMessage_SessionLockRequiredImplCopyWith(
    _$AppMessage_SessionLockRequiredImpl value,
    $Res Function(_$AppMessage_SessionLockRequiredImpl) then,
  ) = __$$AppMessage_SessionLockRequiredImplCopyWithImpl<$Res>;
}

/// @nodoc
class __$$AppMessage_SessionLockRequiredImplCopyWithImpl<$Res>
    extends _$AppMessageCopyWithImpl<$Res, _$AppMessage_SessionLockRequiredImpl>
    implements _$$AppMessage_SessionLockRequiredImplCopyWith<$Res> {
  __$$AppMessage_SessionLockRequiredImplCopyWithImpl(
    _$AppMessage_SessionLockRequiredImpl _value,
    $Res Function(_$AppMessage_SessionLockRequiredImpl) _then,
  ) : super(_value, _then);

  /// Create a copy of AppMessage
  /// with the given fields replaced by the non-null parameter values.
}

/// @nodoc

class _$AppMessage_SessionLockRequiredImpl
    extends AppMessage_SessionLockRequired {
  const _$AppMessage_SessionLockRequiredImpl() : super._();

  @override
  String toString() {
    return 'AppMessage.sessionLockRequired()';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$AppMessage_SessionLockRequiredImpl);
  }

  @override
  int get hashCode => runtimeType.hashCode;

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function(AgentRequest event) agentEvent,
    required TResult Function(BusCsrEvent event) busEvent,
    required TResult Function() sessionLockRequired,
  }) {
    return sessionLockRequired();
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function(AgentRequest event)? agentEvent,
    TResult? Function(BusCsrEvent event)? busEvent,
    TResult? Function()? sessionLockRequired,
  }) {
    return sessionLockRequired?.call();
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function(AgentRequest event)? agentEvent,
    TResult Function(BusCsrEvent event)? busEvent,
    TResult Function()? sessionLockRequired,
    required TResult orElse(),
  }) {
    if (sessionLockRequired != null) {
      return sessionLockRequired();
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(AppMessage_AgentEvent value) agentEvent,
    required TResult Function(AppMessage_BusEvent value) busEvent,
    required TResult Function(AppMessage_SessionLockRequired value)
    sessionLockRequired,
  }) {
    return sessionLockRequired(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(AppMessage_AgentEvent value)? agentEvent,
    TResult? Function(AppMessage_BusEvent value)? busEvent,
    TResult? Function(AppMessage_SessionLockRequired value)?
    sessionLockRequired,
  }) {
    return sessionLockRequired?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(AppMessage_AgentEvent value)? agentEvent,
    TResult Function(AppMessage_BusEvent value)? busEvent,
    TResult Function(AppMessage_SessionLockRequired value)? sessionLockRequired,
    required TResult orElse(),
  }) {
    if (sessionLockRequired != null) {
      return sessionLockRequired(this);
    }
    return orElse();
  }
}

abstract class AppMessage_SessionLockRequired extends AppMessage {
  const factory AppMessage_SessionLockRequired() =
      _$AppMessage_SessionLockRequiredImpl;
  const AppMessage_SessionLockRequired._() : super._();
}

/// @nodoc
mixin _$MxVerifyEvent {
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function() waiting,
    required TResult Function() requestReceived,
    required TResult Function(List<MxEmojiInfo> emojis) emojis,
    required TResult Function() done,
    required TResult Function(String reason) cancelled,
  }) => throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function()? waiting,
    TResult? Function()? requestReceived,
    TResult? Function(List<MxEmojiInfo> emojis)? emojis,
    TResult? Function()? done,
    TResult? Function(String reason)? cancelled,
  }) => throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function()? waiting,
    TResult Function()? requestReceived,
    TResult Function(List<MxEmojiInfo> emojis)? emojis,
    TResult Function()? done,
    TResult Function(String reason)? cancelled,
    required TResult orElse(),
  }) => throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(MxVerifyEvent_Waiting value) waiting,
    required TResult Function(MxVerifyEvent_RequestReceived value)
    requestReceived,
    required TResult Function(MxVerifyEvent_Emojis value) emojis,
    required TResult Function(MxVerifyEvent_Done value) done,
    required TResult Function(MxVerifyEvent_Cancelled value) cancelled,
  }) => throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(MxVerifyEvent_Waiting value)? waiting,
    TResult? Function(MxVerifyEvent_RequestReceived value)? requestReceived,
    TResult? Function(MxVerifyEvent_Emojis value)? emojis,
    TResult? Function(MxVerifyEvent_Done value)? done,
    TResult? Function(MxVerifyEvent_Cancelled value)? cancelled,
  }) => throw _privateConstructorUsedError;
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(MxVerifyEvent_Waiting value)? waiting,
    TResult Function(MxVerifyEvent_RequestReceived value)? requestReceived,
    TResult Function(MxVerifyEvent_Emojis value)? emojis,
    TResult Function(MxVerifyEvent_Done value)? done,
    TResult Function(MxVerifyEvent_Cancelled value)? cancelled,
    required TResult orElse(),
  }) => throw _privateConstructorUsedError;
}

/// @nodoc
abstract class $MxVerifyEventCopyWith<$Res> {
  factory $MxVerifyEventCopyWith(
    MxVerifyEvent value,
    $Res Function(MxVerifyEvent) then,
  ) = _$MxVerifyEventCopyWithImpl<$Res, MxVerifyEvent>;
}

/// @nodoc
class _$MxVerifyEventCopyWithImpl<$Res, $Val extends MxVerifyEvent>
    implements $MxVerifyEventCopyWith<$Res> {
  _$MxVerifyEventCopyWithImpl(this._value, this._then);

  // ignore: unused_field
  final $Val _value;
  // ignore: unused_field
  final $Res Function($Val) _then;

  /// Create a copy of MxVerifyEvent
  /// with the given fields replaced by the non-null parameter values.
}

/// @nodoc
abstract class _$$MxVerifyEvent_WaitingImplCopyWith<$Res> {
  factory _$$MxVerifyEvent_WaitingImplCopyWith(
    _$MxVerifyEvent_WaitingImpl value,
    $Res Function(_$MxVerifyEvent_WaitingImpl) then,
  ) = __$$MxVerifyEvent_WaitingImplCopyWithImpl<$Res>;
}

/// @nodoc
class __$$MxVerifyEvent_WaitingImplCopyWithImpl<$Res>
    extends _$MxVerifyEventCopyWithImpl<$Res, _$MxVerifyEvent_WaitingImpl>
    implements _$$MxVerifyEvent_WaitingImplCopyWith<$Res> {
  __$$MxVerifyEvent_WaitingImplCopyWithImpl(
    _$MxVerifyEvent_WaitingImpl _value,
    $Res Function(_$MxVerifyEvent_WaitingImpl) _then,
  ) : super(_value, _then);

  /// Create a copy of MxVerifyEvent
  /// with the given fields replaced by the non-null parameter values.
}

/// @nodoc

class _$MxVerifyEvent_WaitingImpl extends MxVerifyEvent_Waiting {
  const _$MxVerifyEvent_WaitingImpl() : super._();

  @override
  String toString() {
    return 'MxVerifyEvent.waiting()';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$MxVerifyEvent_WaitingImpl);
  }

  @override
  int get hashCode => runtimeType.hashCode;

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function() waiting,
    required TResult Function() requestReceived,
    required TResult Function(List<MxEmojiInfo> emojis) emojis,
    required TResult Function() done,
    required TResult Function(String reason) cancelled,
  }) {
    return waiting();
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function()? waiting,
    TResult? Function()? requestReceived,
    TResult? Function(List<MxEmojiInfo> emojis)? emojis,
    TResult? Function()? done,
    TResult? Function(String reason)? cancelled,
  }) {
    return waiting?.call();
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function()? waiting,
    TResult Function()? requestReceived,
    TResult Function(List<MxEmojiInfo> emojis)? emojis,
    TResult Function()? done,
    TResult Function(String reason)? cancelled,
    required TResult orElse(),
  }) {
    if (waiting != null) {
      return waiting();
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(MxVerifyEvent_Waiting value) waiting,
    required TResult Function(MxVerifyEvent_RequestReceived value)
    requestReceived,
    required TResult Function(MxVerifyEvent_Emojis value) emojis,
    required TResult Function(MxVerifyEvent_Done value) done,
    required TResult Function(MxVerifyEvent_Cancelled value) cancelled,
  }) {
    return waiting(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(MxVerifyEvent_Waiting value)? waiting,
    TResult? Function(MxVerifyEvent_RequestReceived value)? requestReceived,
    TResult? Function(MxVerifyEvent_Emojis value)? emojis,
    TResult? Function(MxVerifyEvent_Done value)? done,
    TResult? Function(MxVerifyEvent_Cancelled value)? cancelled,
  }) {
    return waiting?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(MxVerifyEvent_Waiting value)? waiting,
    TResult Function(MxVerifyEvent_RequestReceived value)? requestReceived,
    TResult Function(MxVerifyEvent_Emojis value)? emojis,
    TResult Function(MxVerifyEvent_Done value)? done,
    TResult Function(MxVerifyEvent_Cancelled value)? cancelled,
    required TResult orElse(),
  }) {
    if (waiting != null) {
      return waiting(this);
    }
    return orElse();
  }
}

abstract class MxVerifyEvent_Waiting extends MxVerifyEvent {
  const factory MxVerifyEvent_Waiting() = _$MxVerifyEvent_WaitingImpl;
  const MxVerifyEvent_Waiting._() : super._();
}

/// @nodoc
abstract class _$$MxVerifyEvent_RequestReceivedImplCopyWith<$Res> {
  factory _$$MxVerifyEvent_RequestReceivedImplCopyWith(
    _$MxVerifyEvent_RequestReceivedImpl value,
    $Res Function(_$MxVerifyEvent_RequestReceivedImpl) then,
  ) = __$$MxVerifyEvent_RequestReceivedImplCopyWithImpl<$Res>;
}

/// @nodoc
class __$$MxVerifyEvent_RequestReceivedImplCopyWithImpl<$Res>
    extends
        _$MxVerifyEventCopyWithImpl<$Res, _$MxVerifyEvent_RequestReceivedImpl>
    implements _$$MxVerifyEvent_RequestReceivedImplCopyWith<$Res> {
  __$$MxVerifyEvent_RequestReceivedImplCopyWithImpl(
    _$MxVerifyEvent_RequestReceivedImpl _value,
    $Res Function(_$MxVerifyEvent_RequestReceivedImpl) _then,
  ) : super(_value, _then);

  /// Create a copy of MxVerifyEvent
  /// with the given fields replaced by the non-null parameter values.
}

/// @nodoc

class _$MxVerifyEvent_RequestReceivedImpl
    extends MxVerifyEvent_RequestReceived {
  const _$MxVerifyEvent_RequestReceivedImpl() : super._();

  @override
  String toString() {
    return 'MxVerifyEvent.requestReceived()';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$MxVerifyEvent_RequestReceivedImpl);
  }

  @override
  int get hashCode => runtimeType.hashCode;

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function() waiting,
    required TResult Function() requestReceived,
    required TResult Function(List<MxEmojiInfo> emojis) emojis,
    required TResult Function() done,
    required TResult Function(String reason) cancelled,
  }) {
    return requestReceived();
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function()? waiting,
    TResult? Function()? requestReceived,
    TResult? Function(List<MxEmojiInfo> emojis)? emojis,
    TResult? Function()? done,
    TResult? Function(String reason)? cancelled,
  }) {
    return requestReceived?.call();
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function()? waiting,
    TResult Function()? requestReceived,
    TResult Function(List<MxEmojiInfo> emojis)? emojis,
    TResult Function()? done,
    TResult Function(String reason)? cancelled,
    required TResult orElse(),
  }) {
    if (requestReceived != null) {
      return requestReceived();
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(MxVerifyEvent_Waiting value) waiting,
    required TResult Function(MxVerifyEvent_RequestReceived value)
    requestReceived,
    required TResult Function(MxVerifyEvent_Emojis value) emojis,
    required TResult Function(MxVerifyEvent_Done value) done,
    required TResult Function(MxVerifyEvent_Cancelled value) cancelled,
  }) {
    return requestReceived(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(MxVerifyEvent_Waiting value)? waiting,
    TResult? Function(MxVerifyEvent_RequestReceived value)? requestReceived,
    TResult? Function(MxVerifyEvent_Emojis value)? emojis,
    TResult? Function(MxVerifyEvent_Done value)? done,
    TResult? Function(MxVerifyEvent_Cancelled value)? cancelled,
  }) {
    return requestReceived?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(MxVerifyEvent_Waiting value)? waiting,
    TResult Function(MxVerifyEvent_RequestReceived value)? requestReceived,
    TResult Function(MxVerifyEvent_Emojis value)? emojis,
    TResult Function(MxVerifyEvent_Done value)? done,
    TResult Function(MxVerifyEvent_Cancelled value)? cancelled,
    required TResult orElse(),
  }) {
    if (requestReceived != null) {
      return requestReceived(this);
    }
    return orElse();
  }
}

abstract class MxVerifyEvent_RequestReceived extends MxVerifyEvent {
  const factory MxVerifyEvent_RequestReceived() =
      _$MxVerifyEvent_RequestReceivedImpl;
  const MxVerifyEvent_RequestReceived._() : super._();
}

/// @nodoc
abstract class _$$MxVerifyEvent_EmojisImplCopyWith<$Res> {
  factory _$$MxVerifyEvent_EmojisImplCopyWith(
    _$MxVerifyEvent_EmojisImpl value,
    $Res Function(_$MxVerifyEvent_EmojisImpl) then,
  ) = __$$MxVerifyEvent_EmojisImplCopyWithImpl<$Res>;
  @useResult
  $Res call({List<MxEmojiInfo> emojis});
}

/// @nodoc
class __$$MxVerifyEvent_EmojisImplCopyWithImpl<$Res>
    extends _$MxVerifyEventCopyWithImpl<$Res, _$MxVerifyEvent_EmojisImpl>
    implements _$$MxVerifyEvent_EmojisImplCopyWith<$Res> {
  __$$MxVerifyEvent_EmojisImplCopyWithImpl(
    _$MxVerifyEvent_EmojisImpl _value,
    $Res Function(_$MxVerifyEvent_EmojisImpl) _then,
  ) : super(_value, _then);

  /// Create a copy of MxVerifyEvent
  /// with the given fields replaced by the non-null parameter values.
  @pragma('vm:prefer-inline')
  @override
  $Res call({Object? emojis = null}) {
    return _then(
      _$MxVerifyEvent_EmojisImpl(
        emojis: null == emojis
            ? _value._emojis
            : emojis // ignore: cast_nullable_to_non_nullable
                  as List<MxEmojiInfo>,
      ),
    );
  }
}

/// @nodoc

class _$MxVerifyEvent_EmojisImpl extends MxVerifyEvent_Emojis {
  const _$MxVerifyEvent_EmojisImpl({required final List<MxEmojiInfo> emojis})
    : _emojis = emojis,
      super._();

  final List<MxEmojiInfo> _emojis;
  @override
  List<MxEmojiInfo> get emojis {
    if (_emojis is EqualUnmodifiableListView) return _emojis;
    // ignore: implicit_dynamic_type
    return EqualUnmodifiableListView(_emojis);
  }

  @override
  String toString() {
    return 'MxVerifyEvent.emojis(emojis: $emojis)';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$MxVerifyEvent_EmojisImpl &&
            const DeepCollectionEquality().equals(other._emojis, _emojis));
  }

  @override
  int get hashCode =>
      Object.hash(runtimeType, const DeepCollectionEquality().hash(_emojis));

  /// Create a copy of MxVerifyEvent
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  @override
  @pragma('vm:prefer-inline')
  _$$MxVerifyEvent_EmojisImplCopyWith<_$MxVerifyEvent_EmojisImpl>
  get copyWith =>
      __$$MxVerifyEvent_EmojisImplCopyWithImpl<_$MxVerifyEvent_EmojisImpl>(
        this,
        _$identity,
      );

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function() waiting,
    required TResult Function() requestReceived,
    required TResult Function(List<MxEmojiInfo> emojis) emojis,
    required TResult Function() done,
    required TResult Function(String reason) cancelled,
  }) {
    return emojis(this.emojis);
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function()? waiting,
    TResult? Function()? requestReceived,
    TResult? Function(List<MxEmojiInfo> emojis)? emojis,
    TResult? Function()? done,
    TResult? Function(String reason)? cancelled,
  }) {
    return emojis?.call(this.emojis);
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function()? waiting,
    TResult Function()? requestReceived,
    TResult Function(List<MxEmojiInfo> emojis)? emojis,
    TResult Function()? done,
    TResult Function(String reason)? cancelled,
    required TResult orElse(),
  }) {
    if (emojis != null) {
      return emojis(this.emojis);
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(MxVerifyEvent_Waiting value) waiting,
    required TResult Function(MxVerifyEvent_RequestReceived value)
    requestReceived,
    required TResult Function(MxVerifyEvent_Emojis value) emojis,
    required TResult Function(MxVerifyEvent_Done value) done,
    required TResult Function(MxVerifyEvent_Cancelled value) cancelled,
  }) {
    return emojis(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(MxVerifyEvent_Waiting value)? waiting,
    TResult? Function(MxVerifyEvent_RequestReceived value)? requestReceived,
    TResult? Function(MxVerifyEvent_Emojis value)? emojis,
    TResult? Function(MxVerifyEvent_Done value)? done,
    TResult? Function(MxVerifyEvent_Cancelled value)? cancelled,
  }) {
    return emojis?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(MxVerifyEvent_Waiting value)? waiting,
    TResult Function(MxVerifyEvent_RequestReceived value)? requestReceived,
    TResult Function(MxVerifyEvent_Emojis value)? emojis,
    TResult Function(MxVerifyEvent_Done value)? done,
    TResult Function(MxVerifyEvent_Cancelled value)? cancelled,
    required TResult orElse(),
  }) {
    if (emojis != null) {
      return emojis(this);
    }
    return orElse();
  }
}

abstract class MxVerifyEvent_Emojis extends MxVerifyEvent {
  const factory MxVerifyEvent_Emojis({
    required final List<MxEmojiInfo> emojis,
  }) = _$MxVerifyEvent_EmojisImpl;
  const MxVerifyEvent_Emojis._() : super._();

  List<MxEmojiInfo> get emojis;

  /// Create a copy of MxVerifyEvent
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  _$$MxVerifyEvent_EmojisImplCopyWith<_$MxVerifyEvent_EmojisImpl>
  get copyWith => throw _privateConstructorUsedError;
}

/// @nodoc
abstract class _$$MxVerifyEvent_DoneImplCopyWith<$Res> {
  factory _$$MxVerifyEvent_DoneImplCopyWith(
    _$MxVerifyEvent_DoneImpl value,
    $Res Function(_$MxVerifyEvent_DoneImpl) then,
  ) = __$$MxVerifyEvent_DoneImplCopyWithImpl<$Res>;
}

/// @nodoc
class __$$MxVerifyEvent_DoneImplCopyWithImpl<$Res>
    extends _$MxVerifyEventCopyWithImpl<$Res, _$MxVerifyEvent_DoneImpl>
    implements _$$MxVerifyEvent_DoneImplCopyWith<$Res> {
  __$$MxVerifyEvent_DoneImplCopyWithImpl(
    _$MxVerifyEvent_DoneImpl _value,
    $Res Function(_$MxVerifyEvent_DoneImpl) _then,
  ) : super(_value, _then);

  /// Create a copy of MxVerifyEvent
  /// with the given fields replaced by the non-null parameter values.
}

/// @nodoc

class _$MxVerifyEvent_DoneImpl extends MxVerifyEvent_Done {
  const _$MxVerifyEvent_DoneImpl() : super._();

  @override
  String toString() {
    return 'MxVerifyEvent.done()';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType && other is _$MxVerifyEvent_DoneImpl);
  }

  @override
  int get hashCode => runtimeType.hashCode;

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function() waiting,
    required TResult Function() requestReceived,
    required TResult Function(List<MxEmojiInfo> emojis) emojis,
    required TResult Function() done,
    required TResult Function(String reason) cancelled,
  }) {
    return done();
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function()? waiting,
    TResult? Function()? requestReceived,
    TResult? Function(List<MxEmojiInfo> emojis)? emojis,
    TResult? Function()? done,
    TResult? Function(String reason)? cancelled,
  }) {
    return done?.call();
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function()? waiting,
    TResult Function()? requestReceived,
    TResult Function(List<MxEmojiInfo> emojis)? emojis,
    TResult Function()? done,
    TResult Function(String reason)? cancelled,
    required TResult orElse(),
  }) {
    if (done != null) {
      return done();
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(MxVerifyEvent_Waiting value) waiting,
    required TResult Function(MxVerifyEvent_RequestReceived value)
    requestReceived,
    required TResult Function(MxVerifyEvent_Emojis value) emojis,
    required TResult Function(MxVerifyEvent_Done value) done,
    required TResult Function(MxVerifyEvent_Cancelled value) cancelled,
  }) {
    return done(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(MxVerifyEvent_Waiting value)? waiting,
    TResult? Function(MxVerifyEvent_RequestReceived value)? requestReceived,
    TResult? Function(MxVerifyEvent_Emojis value)? emojis,
    TResult? Function(MxVerifyEvent_Done value)? done,
    TResult? Function(MxVerifyEvent_Cancelled value)? cancelled,
  }) {
    return done?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(MxVerifyEvent_Waiting value)? waiting,
    TResult Function(MxVerifyEvent_RequestReceived value)? requestReceived,
    TResult Function(MxVerifyEvent_Emojis value)? emojis,
    TResult Function(MxVerifyEvent_Done value)? done,
    TResult Function(MxVerifyEvent_Cancelled value)? cancelled,
    required TResult orElse(),
  }) {
    if (done != null) {
      return done(this);
    }
    return orElse();
  }
}

abstract class MxVerifyEvent_Done extends MxVerifyEvent {
  const factory MxVerifyEvent_Done() = _$MxVerifyEvent_DoneImpl;
  const MxVerifyEvent_Done._() : super._();
}

/// @nodoc
abstract class _$$MxVerifyEvent_CancelledImplCopyWith<$Res> {
  factory _$$MxVerifyEvent_CancelledImplCopyWith(
    _$MxVerifyEvent_CancelledImpl value,
    $Res Function(_$MxVerifyEvent_CancelledImpl) then,
  ) = __$$MxVerifyEvent_CancelledImplCopyWithImpl<$Res>;
  @useResult
  $Res call({String reason});
}

/// @nodoc
class __$$MxVerifyEvent_CancelledImplCopyWithImpl<$Res>
    extends _$MxVerifyEventCopyWithImpl<$Res, _$MxVerifyEvent_CancelledImpl>
    implements _$$MxVerifyEvent_CancelledImplCopyWith<$Res> {
  __$$MxVerifyEvent_CancelledImplCopyWithImpl(
    _$MxVerifyEvent_CancelledImpl _value,
    $Res Function(_$MxVerifyEvent_CancelledImpl) _then,
  ) : super(_value, _then);

  /// Create a copy of MxVerifyEvent
  /// with the given fields replaced by the non-null parameter values.
  @pragma('vm:prefer-inline')
  @override
  $Res call({Object? reason = null}) {
    return _then(
      _$MxVerifyEvent_CancelledImpl(
        reason: null == reason
            ? _value.reason
            : reason // ignore: cast_nullable_to_non_nullable
                  as String,
      ),
    );
  }
}

/// @nodoc

class _$MxVerifyEvent_CancelledImpl extends MxVerifyEvent_Cancelled {
  const _$MxVerifyEvent_CancelledImpl({required this.reason}) : super._();

  @override
  final String reason;

  @override
  String toString() {
    return 'MxVerifyEvent.cancelled(reason: $reason)';
  }

  @override
  bool operator ==(Object other) {
    return identical(this, other) ||
        (other.runtimeType == runtimeType &&
            other is _$MxVerifyEvent_CancelledImpl &&
            (identical(other.reason, reason) || other.reason == reason));
  }

  @override
  int get hashCode => Object.hash(runtimeType, reason);

  /// Create a copy of MxVerifyEvent
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  @override
  @pragma('vm:prefer-inline')
  _$$MxVerifyEvent_CancelledImplCopyWith<_$MxVerifyEvent_CancelledImpl>
  get copyWith =>
      __$$MxVerifyEvent_CancelledImplCopyWithImpl<
        _$MxVerifyEvent_CancelledImpl
      >(this, _$identity);

  @override
  @optionalTypeArgs
  TResult when<TResult extends Object?>({
    required TResult Function() waiting,
    required TResult Function() requestReceived,
    required TResult Function(List<MxEmojiInfo> emojis) emojis,
    required TResult Function() done,
    required TResult Function(String reason) cancelled,
  }) {
    return cancelled(reason);
  }

  @override
  @optionalTypeArgs
  TResult? whenOrNull<TResult extends Object?>({
    TResult? Function()? waiting,
    TResult? Function()? requestReceived,
    TResult? Function(List<MxEmojiInfo> emojis)? emojis,
    TResult? Function()? done,
    TResult? Function(String reason)? cancelled,
  }) {
    return cancelled?.call(reason);
  }

  @override
  @optionalTypeArgs
  TResult maybeWhen<TResult extends Object?>({
    TResult Function()? waiting,
    TResult Function()? requestReceived,
    TResult Function(List<MxEmojiInfo> emojis)? emojis,
    TResult Function()? done,
    TResult Function(String reason)? cancelled,
    required TResult orElse(),
  }) {
    if (cancelled != null) {
      return cancelled(reason);
    }
    return orElse();
  }

  @override
  @optionalTypeArgs
  TResult map<TResult extends Object?>({
    required TResult Function(MxVerifyEvent_Waiting value) waiting,
    required TResult Function(MxVerifyEvent_RequestReceived value)
    requestReceived,
    required TResult Function(MxVerifyEvent_Emojis value) emojis,
    required TResult Function(MxVerifyEvent_Done value) done,
    required TResult Function(MxVerifyEvent_Cancelled value) cancelled,
  }) {
    return cancelled(this);
  }

  @override
  @optionalTypeArgs
  TResult? mapOrNull<TResult extends Object?>({
    TResult? Function(MxVerifyEvent_Waiting value)? waiting,
    TResult? Function(MxVerifyEvent_RequestReceived value)? requestReceived,
    TResult? Function(MxVerifyEvent_Emojis value)? emojis,
    TResult? Function(MxVerifyEvent_Done value)? done,
    TResult? Function(MxVerifyEvent_Cancelled value)? cancelled,
  }) {
    return cancelled?.call(this);
  }

  @override
  @optionalTypeArgs
  TResult maybeMap<TResult extends Object?>({
    TResult Function(MxVerifyEvent_Waiting value)? waiting,
    TResult Function(MxVerifyEvent_RequestReceived value)? requestReceived,
    TResult Function(MxVerifyEvent_Emojis value)? emojis,
    TResult Function(MxVerifyEvent_Done value)? done,
    TResult Function(MxVerifyEvent_Cancelled value)? cancelled,
    required TResult orElse(),
  }) {
    if (cancelled != null) {
      return cancelled(this);
    }
    return orElse();
  }
}

abstract class MxVerifyEvent_Cancelled extends MxVerifyEvent {
  const factory MxVerifyEvent_Cancelled({required final String reason}) =
      _$MxVerifyEvent_CancelledImpl;
  const MxVerifyEvent_Cancelled._() : super._();

  String get reason;

  /// Create a copy of MxVerifyEvent
  /// with the given fields replaced by the non-null parameter values.
  @JsonKey(includeFromJson: false, includeToJson: false)
  _$$MxVerifyEvent_CancelledImplCopyWith<_$MxVerifyEvent_CancelledImpl>
  get copyWith => throw _privateConstructorUsedError;
}
