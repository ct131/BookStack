<?php

namespace BookStack\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Auth;
use BookStack\Users\Models\User;
use Illuminate\Support\Str;

class OpsAnySsoMiddleware
{
    // OpsAny 用户信息 API
    protected string $userInfoApi = 'https://172.31.1.30/o/workbench/api/workbench/v0_1/user-info/';

    public function handle(Request $request, Closure $next)
    {
        logger()->info('[OPSANY SSO] Incoming request', [
            'url' => $request->fullUrl(),
            'cookie' => $request->header('Cookie'),
            'headers' => $request->headers->all(),
        ]);

        // 1️⃣ 已登录，直接放行
        if (Auth::check()) {
            return $next($request);
        }

        try {
            // 2️⃣ 调用 OpsAny user-info API（带 Cookie，跳过 SSL 验证）
            $response = Http::withHeaders([
                'Cookie' => $request->header('Cookie'),
            ])->withOptions(['verify' => false])
                ->get($this->userInfoApi);

            // 3️⃣ 输出调试日志
            logger()->info('[OPSANY SSO] API response', [
                'status' => $response->status(),
                'body' => $response->body(),
                'json' => $response->json(),
            ]);

            if (!$response->ok()) {
                logger()->error('[OPSANY SSO] API request failed', ['status' => $response->status()]);
                return $next($request); // 可选择 abort(401) 或继续访问
            }

            $data = $response->json('data');

            if (!$data || empty($data['username'])) {
                logger()->error('[OPSANY SSO] Invalid API response', ['data' => $data]);
                return $next($request);
            }

            $username = $data['username'];
            $email = $data['email'] ?? $username . '@opsany.local';

            // 4️⃣ 查找或创建 BookStack 用户
            $user = User::where('email', $email)->first();

            if (!$user) {
                $user = new User();
                $user->name = $username;
                $user->email = $email;
                $user->password = bcrypt(Str::random(32));
                // 自动生成唯一 slug
                $baseSlug = Str::slug($username);
                $slug = $baseSlug;
                $counter = 1;
                while (User::where('slug', $slug)->exists()) {
                    $slug = $baseSlug . '-' . $counter;
                    $counter++;
                }
                $user->slug = $slug;
                $user->save();
                $user->attachDefaultRole();
            }

            // 5️⃣ 登录 BookStack
            Auth::login($user);

            logger()->info('[OPSANY SSO] User logged in', ['username' => $username, 'email' => $email]);

        } catch (\Exception $e) {
            logger()->error('[OPSANY SSO] Request exception', ['error' => $e->getMessage()]);
            // 可选择 abort(500) 或继续访问
            return $next($request);
        }

        return $next($request);
    }
}