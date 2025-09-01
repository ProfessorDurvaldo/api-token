<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Carbon\Carbon;
use App\Models\User;

/**
 * Gera token numérico de 10 dígitos
 */
function makeToken($length = 10) {
    $s = '';
    for ($i=0; $i<$length; $i++) {
        $s .= random_int(0,9);
    }
    return $s;
}

/**
 * Cria registro na tabela de tokens e retorna o token em claro
 */
function issueToken($userId, $name, $abilities, $ttlMinutes) {
    $tokenPlain  = makeToken();                     // ex: "5829103746"
    $hashed = hash('sha256', $tokenPlain);
    $now    = Carbon::now();
    $exp    = $now->copy()->addMinutes($ttlMinutes);

    DB::table('personal_access_tokens')->insert([
        'tokenable_type' => User::class,
        'tokenable_id'   => $userId,
        'name'           => $name, // "access" ou "refresh"
        'token'          => $hashed,
        'abilities'      => json_encode($abilities),
        'expires_at'     => $exp,
        'created_at'     => $now,
        'updated_at'     => $now,
    ]);

    return ['plain' => $tokenPlain, 'expires_at' => $exp->toIso8601String()];
}

/**
 * Valida token do header Authorization
 */
function checkAccess(Request $request, $ability = null) {
    $tokenPlain = $request->bearerToken();
    if (!$tokenPlain) return null;

    $token = DB::table('personal_access_tokens')->where('token', hash('sha256', $tokenPlain))->first();
    if (!$token) return null;

    if ($token->expires_at && Carbon::parse($token->expires_at)->isPast()) {
        DB::table('personal_access_tokens')->where('id', $token->id)->delete();
        return null;
    }

    $abilities = json_decode($token->abilities ?: '[]', true);
    if ($ability && !in_array($ability, $abilities) && !in_array('*', $abilities)) {
        return null;
    }

    return $token;
}

/**
 * -------- ROTAS --------
 */

Route::post('/login', function (Request $request) {
    $data = $request->validate([
        'email' => ['required','email'],
        'password' => ['required','string'],
    ]);

    $user = User::where('email', $data['email'])->first();
    if (!$user || !Hash::check($data['password'], $user->password)) {
        return response()->json(['message'=>'Credenciais inválidas'], 401);
    }

    $access  = issueToken($user->id, 'access',  ['*'], 30);        // 30 min
    $refresh = issueToken($user->id, 'refresh', ['refresh'], 60*24); // 1 dia

    return response()->json([
        'access_token'  => $access['plain'],
        'refresh_token' => $refresh['plain'],
        'expires_in'    => 30*60,
        'user'          => $user,
    ]);
});

Route::get('/profile', function (Request $request) {
    $token = checkAccess($request);
    if (!$token) return response()->json(['message'=>'Não autenticado'], 401);

    $user = User::find($token->tokenable_id);
    return response()->json(['message'=>'Acesso liberado', 'user'=>$user]);
});

Route::post('/refresh', function (Request $request) {
    $data = $request->validate(['refresh_token'=>'required|string']);
    $token = DB::table('personal_access_tokens')->where('token', hash('sha256',$data['refresh_token']))->first();
    if (!$token) return response()->json(['message'=>'Refresh inválido'], 401);

    if ($token->expires_at && Carbon::parse($token->expires_at)->isPast()) {
        return response()->json(['message'=>'Refresh expirado'], 401);
    }

    // apaga refresh antigo
    DB::table('personal_access_tokens')->where('id',$token->id)->delete();

    $access  = issueToken($token->tokenable_id, 'access',  ['*'], 30);
    $refresh = issueToken($token->tokenable_id, 'refresh', ['refresh'], 60*24);

    return response()->json([
        'access_token'  => $access['plain'],
        'refresh_token' => $refresh['plain'],
        'expires_in'    => 30*60,
    ]);
});

Route::post('/logout', function (Request $request) {
    $token = checkAccess($request);
    if (!$token) return response()->json(['message'=>'Não autenticado'], 401);

    DB::table('personal_access_tokens')->where('id', $token->id)->delete();
    return response()->json(['message'=>'Logout ok']);
});
