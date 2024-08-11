<?php

namespace App\Http\Controllers;

use App\Constants\MessageConstants;
use App\Http\Controllers\Controller;
use App\Models\User;
use App\Traits\ApiResponseTrait;
use Illuminate\Support\Facades\Validator;
use Tymon\JWTAuth\Facades\JWTAuth;
use Illuminate\Validation\Rule;
use Illuminate\Support\Facades\Hash;


class AuthController extends Controller
{
    use ApiResponseTrait;
    public function register()
    {
        $validator = Validator::make(request()->all(), [
            'name' => 'required',
            'email' => 'required|email|unique:users',
            'password' => 'required|confirmed|min:8',
        ]);

        if ($validator->fails()) {
            return response()->json($validator->errors(), 400);
        }

        $user = new User;
        $user->name = request()->name;
        $user->email = request()->email;
        $user->password = bcrypt(request()->password);
        $user->save();

        return $this->apiResponse($user, MessageConstants::STORE_SUCCESS, 201);
    }

    public function login()
    {


        $credentials = request(['email', 'password']);

        if (!$token = auth('api')->attempt($credentials)) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }
        return $this->apiResponse($this->respondWithToken($token), MessageConstants::QUERY_EXECUTED, 201);
    }

    public function userProfile()
    {
        return $this->apiResponse(auth('api')->user(), MessageConstants::SHOW_SUCCESS, 200);
    }

    public function logout()
    {
        auth('api')->logout();
        return $this->apiResponse(null, 'Successfully logged out', 200);
    }

    public function refresh()
    {
        return $this->respondWithToken(JWTAuth::refresh());
    }

    protected function respondWithToken($token)
    {
        return response()->json([
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_in' => JWTAuth::factory()->getTTL() * 120
        ]);
    }

    public function update()
    {

        $user = auth('api')->user();
        $validator = Validator::make(request()->all(), [
            'name' => 'required',
            'email' => [
                'required',
                'email',
                Rule::unique('users')->ignore($user->id),
            ],
            'current_password' => 'required',
            'password' => 'required|confirmed|min:8',
        ]);

        if ($validator->fails()) {
            return response()->json($validator->errors(), 400);
        }
        // التحقق من كلمة المرور الحالية
        if (!Hash::check(request()->current_password, $user->password)) {
            return $this->apiResponse(null, 'كلمة المرور الحالية غير صحيحة', 400);
        }

        $user->update(request()->all());
        return $this->apiResponse($user, MessageConstants::UPDATE_SUCCESS, 200);
    }
}
