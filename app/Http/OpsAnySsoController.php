<?php

namespace BookStack\Http;

use BookStack\Users\Models\User;
use BookStack\Users\UserRepo;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;
use Throwable;

class OpsAnySsoController extends Controller
{
    /**
     * OpsAny → BookStack SSO 入口
     */
    public function login(Request $request, UserRepo $userRepo)
    {
        try {
            Log::info('Incoming Cookie', [
                'cookie' => $request->header('Cookie')
            ]);

            /* -------------------------------------------------
             * 1. 获取浏览器传入的 Cookie（完整透传）
             * ------------------------------------------------- */
            $cookie = (string) $request->header('Cookie');

            if ($cookie === '') {
                abort(401, 'Missing Cookie');
            }

            /* -------------------------------------------------
             * 2. 调用 OpsAny user-info 接口
             * ------------------------------------------------- */
            $response = Http::withHeaders([
                'Cookie' => $cookie,
                'Accept' => 'application/json',
            ])
                ->timeout(8)
                ->get('https://172.31.1.30/o/workbench/api/workbench/v0_1/user-info/');

            if (!$response->ok()) {
                abort(401, 'OpsAny user-info request failed');
            }

            $json = $response->json();

            if (
                empty($json['data']) ||
                empty($json['data']['username'])
            ) {
                abort(401, 'Invalid OpsAny user info');
            }

            $data = $json['data'];

            /* -------------------------------------------------
             * 3. 映射 OpsAny 用户字段
             * ------------------------------------------------- */
            $username = $data['username'];
            $email = $data['email'] ?? ($username . '@opsany.local');
            $name = $data['ch_name'] ?? $username;

            /* -------------------------------------------------
             * 4. 查找或创建 BookStack 用户（必须用 UserRepo）
             * ------------------------------------------------- */
            $user = User::query()
                ->where('email', $email)
                ->first();

            if (!$user) {
                $user = $userRepo->create([
                    'name' => $name,
                    'email' => $email,
                    'password' => Str::random(32),
                ]);
            }

            /* -------------------------------------------------
             * 5. 登录 BookStack（生成 session）
             * ------------------------------------------------- */
            Auth::login($user, true);

            /* -------------------------------------------------
             * 6. 跳转首页
             * ------------------------------------------------- */
            return redirect()->intended('/');

        } catch (Throwable $e) {

            // 👉 这里是你调试 unknown error 的关键
            report($e);

            abort(500, 'OpsAny SSO failed');
        }
    }
}