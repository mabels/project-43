// GENERATED CODE - DO NOT MODIFY BY HAND
// coverage:ignore-file
// ignore_for_file: type=lint
// ignore_for_file: unused_element, deprecated_member_use, deprecated_member_use_from_same_package, use_function_type_syntax_for_parameters, unnecessary_const, avoid_init_to_null, invalid_override_different_default_values_named, prefer_expression_function_bodies, annotate_overrides, invalid_annotation_target, unnecessary_question_mark

part of 'simple.dart';

// **************************************************************************
// FreezedGenerator
// **************************************************************************

// dart format off
T _$identity<T>(T value) => value;
/// @nodoc
mixin _$AgentRequest {

 String get requestId;
/// Create a copy of AgentRequest
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$AgentRequestCopyWith<AgentRequest> get copyWith => _$AgentRequestCopyWithImpl<AgentRequest>(this as AgentRequest, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is AgentRequest&&(identical(other.requestId, requestId) || other.requestId == requestId));
}


@override
int get hashCode => Object.hash(runtimeType,requestId);

@override
String toString() {
  return 'AgentRequest(requestId: $requestId)';
}


}

/// @nodoc
abstract mixin class $AgentRequestCopyWith<$Res>  {
  factory $AgentRequestCopyWith(AgentRequest value, $Res Function(AgentRequest) _then) = _$AgentRequestCopyWithImpl;
@useResult
$Res call({
 String requestId
});




}
/// @nodoc
class _$AgentRequestCopyWithImpl<$Res>
    implements $AgentRequestCopyWith<$Res> {
  _$AgentRequestCopyWithImpl(this._self, this._then);

  final AgentRequest _self;
  final $Res Function(AgentRequest) _then;

/// Create a copy of AgentRequest
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') @override $Res call({Object? requestId = null,}) {
  return _then(_self.copyWith(
requestId: null == requestId ? _self.requestId : requestId // ignore: cast_nullable_to_non_nullable
as String,
  ));
}

}


/// Adds pattern-matching-related methods to [AgentRequest].
extension AgentRequestPatterns on AgentRequest {
/// A variant of `map` that fallback to returning `orElse`.
///
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case final Subclass value:
///     return ...;
///   case _:
///     return orElse();
/// }
/// ```

@optionalTypeArgs TResult maybeMap<TResult extends Object?>({TResult Function( AgentRequest_ListKeys value)?  listKeys,TResult Function( AgentRequest_Sign value)?  sign,required TResult orElse(),}){
final _that = this;
switch (_that) {
case AgentRequest_ListKeys() when listKeys != null:
return listKeys(_that);case AgentRequest_Sign() when sign != null:
return sign(_that);case _:
  return orElse();

}
}
/// A `switch`-like method, using callbacks.
///
/// Callbacks receives the raw object, upcasted.
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case final Subclass value:
///     return ...;
///   case final Subclass2 value:
///     return ...;
/// }
/// ```

@optionalTypeArgs TResult map<TResult extends Object?>({required TResult Function( AgentRequest_ListKeys value)  listKeys,required TResult Function( AgentRequest_Sign value)  sign,}){
final _that = this;
switch (_that) {
case AgentRequest_ListKeys():
return listKeys(_that);case AgentRequest_Sign():
return sign(_that);}
}
/// A variant of `map` that fallback to returning `null`.
///
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case final Subclass value:
///     return ...;
///   case _:
///     return null;
/// }
/// ```

@optionalTypeArgs TResult? mapOrNull<TResult extends Object?>({TResult? Function( AgentRequest_ListKeys value)?  listKeys,TResult? Function( AgentRequest_Sign value)?  sign,}){
final _that = this;
switch (_that) {
case AgentRequest_ListKeys() when listKeys != null:
return listKeys(_that);case AgentRequest_Sign() when sign != null:
return sign(_that);case _:
  return null;

}
}
/// A variant of `when` that fallback to an `orElse` callback.
///
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case Subclass(:final field):
///     return ...;
///   case _:
///     return orElse();
/// }
/// ```

@optionalTypeArgs TResult maybeWhen<TResult extends Object?>({TResult Function( String requestId)?  listKeys,TResult Function( String requestId,  String fingerprint,  String description,  String deviceLabel,  String deviceId)?  sign,required TResult orElse(),}) {final _that = this;
switch (_that) {
case AgentRequest_ListKeys() when listKeys != null:
return listKeys(_that.requestId);case AgentRequest_Sign() when sign != null:
return sign(_that.requestId,_that.fingerprint,_that.description,_that.deviceLabel,_that.deviceId);case _:
  return orElse();

}
}
/// A `switch`-like method, using callbacks.
///
/// As opposed to `map`, this offers destructuring.
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case Subclass(:final field):
///     return ...;
///   case Subclass2(:final field2):
///     return ...;
/// }
/// ```

@optionalTypeArgs TResult when<TResult extends Object?>({required TResult Function( String requestId)  listKeys,required TResult Function( String requestId,  String fingerprint,  String description,  String deviceLabel,  String deviceId)  sign,}) {final _that = this;
switch (_that) {
case AgentRequest_ListKeys():
return listKeys(_that.requestId);case AgentRequest_Sign():
return sign(_that.requestId,_that.fingerprint,_that.description,_that.deviceLabel,_that.deviceId);}
}
/// A variant of `when` that fallback to returning `null`
///
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case Subclass(:final field):
///     return ...;
///   case _:
///     return null;
/// }
/// ```

@optionalTypeArgs TResult? whenOrNull<TResult extends Object?>({TResult? Function( String requestId)?  listKeys,TResult? Function( String requestId,  String fingerprint,  String description,  String deviceLabel,  String deviceId)?  sign,}) {final _that = this;
switch (_that) {
case AgentRequest_ListKeys() when listKeys != null:
return listKeys(_that.requestId);case AgentRequest_Sign() when sign != null:
return sign(_that.requestId,_that.fingerprint,_that.description,_that.deviceLabel,_that.deviceId);case _:
  return null;

}
}

}

/// @nodoc


class AgentRequest_ListKeys extends AgentRequest {
  const AgentRequest_ListKeys({required this.requestId}): super._();
  

@override final  String requestId;

/// Create a copy of AgentRequest
/// with the given fields replaced by the non-null parameter values.
@override @JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$AgentRequest_ListKeysCopyWith<AgentRequest_ListKeys> get copyWith => _$AgentRequest_ListKeysCopyWithImpl<AgentRequest_ListKeys>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is AgentRequest_ListKeys&&(identical(other.requestId, requestId) || other.requestId == requestId));
}


@override
int get hashCode => Object.hash(runtimeType,requestId);

@override
String toString() {
  return 'AgentRequest.listKeys(requestId: $requestId)';
}


}

/// @nodoc
abstract mixin class $AgentRequest_ListKeysCopyWith<$Res> implements $AgentRequestCopyWith<$Res> {
  factory $AgentRequest_ListKeysCopyWith(AgentRequest_ListKeys value, $Res Function(AgentRequest_ListKeys) _then) = _$AgentRequest_ListKeysCopyWithImpl;
@override @useResult
$Res call({
 String requestId
});




}
/// @nodoc
class _$AgentRequest_ListKeysCopyWithImpl<$Res>
    implements $AgentRequest_ListKeysCopyWith<$Res> {
  _$AgentRequest_ListKeysCopyWithImpl(this._self, this._then);

  final AgentRequest_ListKeys _self;
  final $Res Function(AgentRequest_ListKeys) _then;

/// Create a copy of AgentRequest
/// with the given fields replaced by the non-null parameter values.
@override @pragma('vm:prefer-inline') $Res call({Object? requestId = null,}) {
  return _then(AgentRequest_ListKeys(
requestId: null == requestId ? _self.requestId : requestId // ignore: cast_nullable_to_non_nullable
as String,
  ));
}


}

/// @nodoc


class AgentRequest_Sign extends AgentRequest {
  const AgentRequest_Sign({required this.requestId, required this.fingerprint, required this.description, required this.deviceLabel, required this.deviceId}): super._();
  

@override final  String requestId;
 final  String fingerprint;
 final  String description;
/// Label from the sender's bus certificate (empty if unauthenticated).
 final  String deviceLabel;
/// Stable device identifier from the sender's bus certificate (empty if unauthenticated).
 final  String deviceId;

/// Create a copy of AgentRequest
/// with the given fields replaced by the non-null parameter values.
@override @JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$AgentRequest_SignCopyWith<AgentRequest_Sign> get copyWith => _$AgentRequest_SignCopyWithImpl<AgentRequest_Sign>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is AgentRequest_Sign&&(identical(other.requestId, requestId) || other.requestId == requestId)&&(identical(other.fingerprint, fingerprint) || other.fingerprint == fingerprint)&&(identical(other.description, description) || other.description == description)&&(identical(other.deviceLabel, deviceLabel) || other.deviceLabel == deviceLabel)&&(identical(other.deviceId, deviceId) || other.deviceId == deviceId));
}


@override
int get hashCode => Object.hash(runtimeType,requestId,fingerprint,description,deviceLabel,deviceId);

@override
String toString() {
  return 'AgentRequest.sign(requestId: $requestId, fingerprint: $fingerprint, description: $description, deviceLabel: $deviceLabel, deviceId: $deviceId)';
}


}

/// @nodoc
abstract mixin class $AgentRequest_SignCopyWith<$Res> implements $AgentRequestCopyWith<$Res> {
  factory $AgentRequest_SignCopyWith(AgentRequest_Sign value, $Res Function(AgentRequest_Sign) _then) = _$AgentRequest_SignCopyWithImpl;
@override @useResult
$Res call({
 String requestId, String fingerprint, String description, String deviceLabel, String deviceId
});




}
/// @nodoc
class _$AgentRequest_SignCopyWithImpl<$Res>
    implements $AgentRequest_SignCopyWith<$Res> {
  _$AgentRequest_SignCopyWithImpl(this._self, this._then);

  final AgentRequest_Sign _self;
  final $Res Function(AgentRequest_Sign) _then;

/// Create a copy of AgentRequest
/// with the given fields replaced by the non-null parameter values.
@override @pragma('vm:prefer-inline') $Res call({Object? requestId = null,Object? fingerprint = null,Object? description = null,Object? deviceLabel = null,Object? deviceId = null,}) {
  return _then(AgentRequest_Sign(
requestId: null == requestId ? _self.requestId : requestId // ignore: cast_nullable_to_non_nullable
as String,fingerprint: null == fingerprint ? _self.fingerprint : fingerprint // ignore: cast_nullable_to_non_nullable
as String,description: null == description ? _self.description : description // ignore: cast_nullable_to_non_nullable
as String,deviceLabel: null == deviceLabel ? _self.deviceLabel : deviceLabel // ignore: cast_nullable_to_non_nullable
as String,deviceId: null == deviceId ? _self.deviceId : deviceId // ignore: cast_nullable_to_non_nullable
as String,
  ));
}


}

/// @nodoc
mixin _$AppMessage {





@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is AppMessage);
}


@override
int get hashCode => runtimeType.hashCode;

@override
String toString() {
  return 'AppMessage()';
}


}

/// @nodoc
class $AppMessageCopyWith<$Res>  {
$AppMessageCopyWith(AppMessage _, $Res Function(AppMessage) __);
}


/// Adds pattern-matching-related methods to [AppMessage].
extension AppMessagePatterns on AppMessage {
/// A variant of `map` that fallback to returning `orElse`.
///
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case final Subclass value:
///     return ...;
///   case _:
///     return orElse();
/// }
/// ```

@optionalTypeArgs TResult maybeMap<TResult extends Object?>({TResult Function( AppMessage_AgentEvent value)?  agentEvent,TResult Function( AppMessage_BusEvent value)?  busEvent,TResult Function( AppMessage_SessionLockRequired value)?  sessionLockRequired,required TResult orElse(),}){
final _that = this;
switch (_that) {
case AppMessage_AgentEvent() when agentEvent != null:
return agentEvent(_that);case AppMessage_BusEvent() when busEvent != null:
return busEvent(_that);case AppMessage_SessionLockRequired() when sessionLockRequired != null:
return sessionLockRequired(_that);case _:
  return orElse();

}
}
/// A `switch`-like method, using callbacks.
///
/// Callbacks receives the raw object, upcasted.
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case final Subclass value:
///     return ...;
///   case final Subclass2 value:
///     return ...;
/// }
/// ```

@optionalTypeArgs TResult map<TResult extends Object?>({required TResult Function( AppMessage_AgentEvent value)  agentEvent,required TResult Function( AppMessage_BusEvent value)  busEvent,required TResult Function( AppMessage_SessionLockRequired value)  sessionLockRequired,}){
final _that = this;
switch (_that) {
case AppMessage_AgentEvent():
return agentEvent(_that);case AppMessage_BusEvent():
return busEvent(_that);case AppMessage_SessionLockRequired():
return sessionLockRequired(_that);}
}
/// A variant of `map` that fallback to returning `null`.
///
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case final Subclass value:
///     return ...;
///   case _:
///     return null;
/// }
/// ```

@optionalTypeArgs TResult? mapOrNull<TResult extends Object?>({TResult? Function( AppMessage_AgentEvent value)?  agentEvent,TResult? Function( AppMessage_BusEvent value)?  busEvent,TResult? Function( AppMessage_SessionLockRequired value)?  sessionLockRequired,}){
final _that = this;
switch (_that) {
case AppMessage_AgentEvent() when agentEvent != null:
return agentEvent(_that);case AppMessage_BusEvent() when busEvent != null:
return busEvent(_that);case AppMessage_SessionLockRequired() when sessionLockRequired != null:
return sessionLockRequired(_that);case _:
  return null;

}
}
/// A variant of `when` that fallback to an `orElse` callback.
///
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case Subclass(:final field):
///     return ...;
///   case _:
///     return orElse();
/// }
/// ```

@optionalTypeArgs TResult maybeWhen<TResult extends Object?>({TResult Function( AgentRequest event)?  agentEvent,TResult Function( BusCsrEvent event)?  busEvent,TResult Function()?  sessionLockRequired,required TResult orElse(),}) {final _that = this;
switch (_that) {
case AppMessage_AgentEvent() when agentEvent != null:
return agentEvent(_that.event);case AppMessage_BusEvent() when busEvent != null:
return busEvent(_that.event);case AppMessage_SessionLockRequired() when sessionLockRequired != null:
return sessionLockRequired();case _:
  return orElse();

}
}
/// A `switch`-like method, using callbacks.
///
/// As opposed to `map`, this offers destructuring.
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case Subclass(:final field):
///     return ...;
///   case Subclass2(:final field2):
///     return ...;
/// }
/// ```

@optionalTypeArgs TResult when<TResult extends Object?>({required TResult Function( AgentRequest event)  agentEvent,required TResult Function( BusCsrEvent event)  busEvent,required TResult Function()  sessionLockRequired,}) {final _that = this;
switch (_that) {
case AppMessage_AgentEvent():
return agentEvent(_that.event);case AppMessage_BusEvent():
return busEvent(_that.event);case AppMessage_SessionLockRequired():
return sessionLockRequired();}
}
/// A variant of `when` that fallback to returning `null`
///
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case Subclass(:final field):
///     return ...;
///   case _:
///     return null;
/// }
/// ```

@optionalTypeArgs TResult? whenOrNull<TResult extends Object?>({TResult? Function( AgentRequest event)?  agentEvent,TResult? Function( BusCsrEvent event)?  busEvent,TResult? Function()?  sessionLockRequired,}) {final _that = this;
switch (_that) {
case AppMessage_AgentEvent() when agentEvent != null:
return agentEvent(_that.event);case AppMessage_BusEvent() when busEvent != null:
return busEvent(_that.event);case AppMessage_SessionLockRequired() when sessionLockRequired != null:
return sessionLockRequired();case _:
  return null;

}
}

}

/// @nodoc


class AppMessage_AgentEvent extends AppMessage {
  const AppMessage_AgentEvent({required this.event}): super._();
  

 final  AgentRequest event;

/// Create a copy of AppMessage
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$AppMessage_AgentEventCopyWith<AppMessage_AgentEvent> get copyWith => _$AppMessage_AgentEventCopyWithImpl<AppMessage_AgentEvent>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is AppMessage_AgentEvent&&(identical(other.event, event) || other.event == event));
}


@override
int get hashCode => Object.hash(runtimeType,event);

@override
String toString() {
  return 'AppMessage.agentEvent(event: $event)';
}


}

/// @nodoc
abstract mixin class $AppMessage_AgentEventCopyWith<$Res> implements $AppMessageCopyWith<$Res> {
  factory $AppMessage_AgentEventCopyWith(AppMessage_AgentEvent value, $Res Function(AppMessage_AgentEvent) _then) = _$AppMessage_AgentEventCopyWithImpl;
@useResult
$Res call({
 AgentRequest event
});


$AgentRequestCopyWith<$Res> get event;

}
/// @nodoc
class _$AppMessage_AgentEventCopyWithImpl<$Res>
    implements $AppMessage_AgentEventCopyWith<$Res> {
  _$AppMessage_AgentEventCopyWithImpl(this._self, this._then);

  final AppMessage_AgentEvent _self;
  final $Res Function(AppMessage_AgentEvent) _then;

/// Create a copy of AppMessage
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? event = null,}) {
  return _then(AppMessage_AgentEvent(
event: null == event ? _self.event : event // ignore: cast_nullable_to_non_nullable
as AgentRequest,
  ));
}

/// Create a copy of AppMessage
/// with the given fields replaced by the non-null parameter values.
@override
@pragma('vm:prefer-inline')
$AgentRequestCopyWith<$Res> get event {
  
  return $AgentRequestCopyWith<$Res>(_self.event, (value) {
    return _then(_self.copyWith(event: value));
  });
}
}

/// @nodoc


class AppMessage_BusEvent extends AppMessage {
  const AppMessage_BusEvent({required this.event}): super._();
  

 final  BusCsrEvent event;

/// Create a copy of AppMessage
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$AppMessage_BusEventCopyWith<AppMessage_BusEvent> get copyWith => _$AppMessage_BusEventCopyWithImpl<AppMessage_BusEvent>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is AppMessage_BusEvent&&(identical(other.event, event) || other.event == event));
}


@override
int get hashCode => Object.hash(runtimeType,event);

@override
String toString() {
  return 'AppMessage.busEvent(event: $event)';
}


}

/// @nodoc
abstract mixin class $AppMessage_BusEventCopyWith<$Res> implements $AppMessageCopyWith<$Res> {
  factory $AppMessage_BusEventCopyWith(AppMessage_BusEvent value, $Res Function(AppMessage_BusEvent) _then) = _$AppMessage_BusEventCopyWithImpl;
@useResult
$Res call({
 BusCsrEvent event
});




}
/// @nodoc
class _$AppMessage_BusEventCopyWithImpl<$Res>
    implements $AppMessage_BusEventCopyWith<$Res> {
  _$AppMessage_BusEventCopyWithImpl(this._self, this._then);

  final AppMessage_BusEvent _self;
  final $Res Function(AppMessage_BusEvent) _then;

/// Create a copy of AppMessage
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? event = null,}) {
  return _then(AppMessage_BusEvent(
event: null == event ? _self.event : event // ignore: cast_nullable_to_non_nullable
as BusCsrEvent,
  ));
}


}

/// @nodoc


class AppMessage_SessionLockRequired extends AppMessage {
  const AppMessage_SessionLockRequired(): super._();
  






@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is AppMessage_SessionLockRequired);
}


@override
int get hashCode => runtimeType.hashCode;

@override
String toString() {
  return 'AppMessage.sessionLockRequired()';
}


}




/// @nodoc
mixin _$MxVerifyEvent {





@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is MxVerifyEvent);
}


@override
int get hashCode => runtimeType.hashCode;

@override
String toString() {
  return 'MxVerifyEvent()';
}


}

/// @nodoc
class $MxVerifyEventCopyWith<$Res>  {
$MxVerifyEventCopyWith(MxVerifyEvent _, $Res Function(MxVerifyEvent) __);
}


/// Adds pattern-matching-related methods to [MxVerifyEvent].
extension MxVerifyEventPatterns on MxVerifyEvent {
/// A variant of `map` that fallback to returning `orElse`.
///
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case final Subclass value:
///     return ...;
///   case _:
///     return orElse();
/// }
/// ```

@optionalTypeArgs TResult maybeMap<TResult extends Object?>({TResult Function( MxVerifyEvent_Waiting value)?  waiting,TResult Function( MxVerifyEvent_RequestReceived value)?  requestReceived,TResult Function( MxVerifyEvent_Emojis value)?  emojis,TResult Function( MxVerifyEvent_Done value)?  done,TResult Function( MxVerifyEvent_Cancelled value)?  cancelled,required TResult orElse(),}){
final _that = this;
switch (_that) {
case MxVerifyEvent_Waiting() when waiting != null:
return waiting(_that);case MxVerifyEvent_RequestReceived() when requestReceived != null:
return requestReceived(_that);case MxVerifyEvent_Emojis() when emojis != null:
return emojis(_that);case MxVerifyEvent_Done() when done != null:
return done(_that);case MxVerifyEvent_Cancelled() when cancelled != null:
return cancelled(_that);case _:
  return orElse();

}
}
/// A `switch`-like method, using callbacks.
///
/// Callbacks receives the raw object, upcasted.
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case final Subclass value:
///     return ...;
///   case final Subclass2 value:
///     return ...;
/// }
/// ```

@optionalTypeArgs TResult map<TResult extends Object?>({required TResult Function( MxVerifyEvent_Waiting value)  waiting,required TResult Function( MxVerifyEvent_RequestReceived value)  requestReceived,required TResult Function( MxVerifyEvent_Emojis value)  emojis,required TResult Function( MxVerifyEvent_Done value)  done,required TResult Function( MxVerifyEvent_Cancelled value)  cancelled,}){
final _that = this;
switch (_that) {
case MxVerifyEvent_Waiting():
return waiting(_that);case MxVerifyEvent_RequestReceived():
return requestReceived(_that);case MxVerifyEvent_Emojis():
return emojis(_that);case MxVerifyEvent_Done():
return done(_that);case MxVerifyEvent_Cancelled():
return cancelled(_that);}
}
/// A variant of `map` that fallback to returning `null`.
///
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case final Subclass value:
///     return ...;
///   case _:
///     return null;
/// }
/// ```

@optionalTypeArgs TResult? mapOrNull<TResult extends Object?>({TResult? Function( MxVerifyEvent_Waiting value)?  waiting,TResult? Function( MxVerifyEvent_RequestReceived value)?  requestReceived,TResult? Function( MxVerifyEvent_Emojis value)?  emojis,TResult? Function( MxVerifyEvent_Done value)?  done,TResult? Function( MxVerifyEvent_Cancelled value)?  cancelled,}){
final _that = this;
switch (_that) {
case MxVerifyEvent_Waiting() when waiting != null:
return waiting(_that);case MxVerifyEvent_RequestReceived() when requestReceived != null:
return requestReceived(_that);case MxVerifyEvent_Emojis() when emojis != null:
return emojis(_that);case MxVerifyEvent_Done() when done != null:
return done(_that);case MxVerifyEvent_Cancelled() when cancelled != null:
return cancelled(_that);case _:
  return null;

}
}
/// A variant of `when` that fallback to an `orElse` callback.
///
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case Subclass(:final field):
///     return ...;
///   case _:
///     return orElse();
/// }
/// ```

@optionalTypeArgs TResult maybeWhen<TResult extends Object?>({TResult Function()?  waiting,TResult Function()?  requestReceived,TResult Function( List<MxEmojiInfo> emojis)?  emojis,TResult Function()?  done,TResult Function( String reason)?  cancelled,required TResult orElse(),}) {final _that = this;
switch (_that) {
case MxVerifyEvent_Waiting() when waiting != null:
return waiting();case MxVerifyEvent_RequestReceived() when requestReceived != null:
return requestReceived();case MxVerifyEvent_Emojis() when emojis != null:
return emojis(_that.emojis);case MxVerifyEvent_Done() when done != null:
return done();case MxVerifyEvent_Cancelled() when cancelled != null:
return cancelled(_that.reason);case _:
  return orElse();

}
}
/// A `switch`-like method, using callbacks.
///
/// As opposed to `map`, this offers destructuring.
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case Subclass(:final field):
///     return ...;
///   case Subclass2(:final field2):
///     return ...;
/// }
/// ```

@optionalTypeArgs TResult when<TResult extends Object?>({required TResult Function()  waiting,required TResult Function()  requestReceived,required TResult Function( List<MxEmojiInfo> emojis)  emojis,required TResult Function()  done,required TResult Function( String reason)  cancelled,}) {final _that = this;
switch (_that) {
case MxVerifyEvent_Waiting():
return waiting();case MxVerifyEvent_RequestReceived():
return requestReceived();case MxVerifyEvent_Emojis():
return emojis(_that.emojis);case MxVerifyEvent_Done():
return done();case MxVerifyEvent_Cancelled():
return cancelled(_that.reason);}
}
/// A variant of `when` that fallback to returning `null`
///
/// It is equivalent to doing:
/// ```dart
/// switch (sealedClass) {
///   case Subclass(:final field):
///     return ...;
///   case _:
///     return null;
/// }
/// ```

@optionalTypeArgs TResult? whenOrNull<TResult extends Object?>({TResult? Function()?  waiting,TResult? Function()?  requestReceived,TResult? Function( List<MxEmojiInfo> emojis)?  emojis,TResult? Function()?  done,TResult? Function( String reason)?  cancelled,}) {final _that = this;
switch (_that) {
case MxVerifyEvent_Waiting() when waiting != null:
return waiting();case MxVerifyEvent_RequestReceived() when requestReceived != null:
return requestReceived();case MxVerifyEvent_Emojis() when emojis != null:
return emojis(_that.emojis);case MxVerifyEvent_Done() when done != null:
return done();case MxVerifyEvent_Cancelled() when cancelled != null:
return cancelled(_that.reason);case _:
  return null;

}
}

}

/// @nodoc


class MxVerifyEvent_Waiting extends MxVerifyEvent {
  const MxVerifyEvent_Waiting(): super._();
  






@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is MxVerifyEvent_Waiting);
}


@override
int get hashCode => runtimeType.hashCode;

@override
String toString() {
  return 'MxVerifyEvent.waiting()';
}


}




/// @nodoc


class MxVerifyEvent_RequestReceived extends MxVerifyEvent {
  const MxVerifyEvent_RequestReceived(): super._();
  






@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is MxVerifyEvent_RequestReceived);
}


@override
int get hashCode => runtimeType.hashCode;

@override
String toString() {
  return 'MxVerifyEvent.requestReceived()';
}


}




/// @nodoc


class MxVerifyEvent_Emojis extends MxVerifyEvent {
  const MxVerifyEvent_Emojis({required final  List<MxEmojiInfo> emojis}): _emojis = emojis,super._();
  

 final  List<MxEmojiInfo> _emojis;
 List<MxEmojiInfo> get emojis {
  if (_emojis is EqualUnmodifiableListView) return _emojis;
  // ignore: implicit_dynamic_type
  return EqualUnmodifiableListView(_emojis);
}


/// Create a copy of MxVerifyEvent
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$MxVerifyEvent_EmojisCopyWith<MxVerifyEvent_Emojis> get copyWith => _$MxVerifyEvent_EmojisCopyWithImpl<MxVerifyEvent_Emojis>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is MxVerifyEvent_Emojis&&const DeepCollectionEquality().equals(other._emojis, _emojis));
}


@override
int get hashCode => Object.hash(runtimeType,const DeepCollectionEquality().hash(_emojis));

@override
String toString() {
  return 'MxVerifyEvent.emojis(emojis: $emojis)';
}


}

/// @nodoc
abstract mixin class $MxVerifyEvent_EmojisCopyWith<$Res> implements $MxVerifyEventCopyWith<$Res> {
  factory $MxVerifyEvent_EmojisCopyWith(MxVerifyEvent_Emojis value, $Res Function(MxVerifyEvent_Emojis) _then) = _$MxVerifyEvent_EmojisCopyWithImpl;
@useResult
$Res call({
 List<MxEmojiInfo> emojis
});




}
/// @nodoc
class _$MxVerifyEvent_EmojisCopyWithImpl<$Res>
    implements $MxVerifyEvent_EmojisCopyWith<$Res> {
  _$MxVerifyEvent_EmojisCopyWithImpl(this._self, this._then);

  final MxVerifyEvent_Emojis _self;
  final $Res Function(MxVerifyEvent_Emojis) _then;

/// Create a copy of MxVerifyEvent
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? emojis = null,}) {
  return _then(MxVerifyEvent_Emojis(
emojis: null == emojis ? _self._emojis : emojis // ignore: cast_nullable_to_non_nullable
as List<MxEmojiInfo>,
  ));
}


}

/// @nodoc


class MxVerifyEvent_Done extends MxVerifyEvent {
  const MxVerifyEvent_Done(): super._();
  






@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is MxVerifyEvent_Done);
}


@override
int get hashCode => runtimeType.hashCode;

@override
String toString() {
  return 'MxVerifyEvent.done()';
}


}




/// @nodoc


class MxVerifyEvent_Cancelled extends MxVerifyEvent {
  const MxVerifyEvent_Cancelled({required this.reason}): super._();
  

 final  String reason;

/// Create a copy of MxVerifyEvent
/// with the given fields replaced by the non-null parameter values.
@JsonKey(includeFromJson: false, includeToJson: false)
@pragma('vm:prefer-inline')
$MxVerifyEvent_CancelledCopyWith<MxVerifyEvent_Cancelled> get copyWith => _$MxVerifyEvent_CancelledCopyWithImpl<MxVerifyEvent_Cancelled>(this, _$identity);



@override
bool operator ==(Object other) {
  return identical(this, other) || (other.runtimeType == runtimeType&&other is MxVerifyEvent_Cancelled&&(identical(other.reason, reason) || other.reason == reason));
}


@override
int get hashCode => Object.hash(runtimeType,reason);

@override
String toString() {
  return 'MxVerifyEvent.cancelled(reason: $reason)';
}


}

/// @nodoc
abstract mixin class $MxVerifyEvent_CancelledCopyWith<$Res> implements $MxVerifyEventCopyWith<$Res> {
  factory $MxVerifyEvent_CancelledCopyWith(MxVerifyEvent_Cancelled value, $Res Function(MxVerifyEvent_Cancelled) _then) = _$MxVerifyEvent_CancelledCopyWithImpl;
@useResult
$Res call({
 String reason
});




}
/// @nodoc
class _$MxVerifyEvent_CancelledCopyWithImpl<$Res>
    implements $MxVerifyEvent_CancelledCopyWith<$Res> {
  _$MxVerifyEvent_CancelledCopyWithImpl(this._self, this._then);

  final MxVerifyEvent_Cancelled _self;
  final $Res Function(MxVerifyEvent_Cancelled) _then;

/// Create a copy of MxVerifyEvent
/// with the given fields replaced by the non-null parameter values.
@pragma('vm:prefer-inline') $Res call({Object? reason = null,}) {
  return _then(MxVerifyEvent_Cancelled(
reason: null == reason ? _self.reason : reason // ignore: cast_nullable_to_non_nullable
as String,
  ));
}


}

// dart format on
