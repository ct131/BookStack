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
        ]);

        try {
            // 1️⃣ 调用 OpsAny user-info API（带 Cookie，跳过 SSL 验证）
            $response = Http::withHeaders([
                'Cookie' => $request->header('Cookie'),
            ])->withOptions([
                'verify' => false,
            ])->get($this->userInfoApi);

            // 2️⃣ 输出 API 调试信息
            logger()->info('[OPSANY SSO] API response', [
                'status' => $response->status(),
                'body'   => $response->body(),
            ]);

            // OpsAny 未登录 / token 失效
            if (!$response->ok()) {
                if (Auth::check()) {
                    logger()->info('[OPSANY SSO] OpsAny logged out, force BookStack logout');
                    Auth::logout();
                    $request->session()->invalidate();
                    $request->session()->regenerateToken();
                }

                return $next($request);
            }

            $data = $response->json('data');

            if (!$data || empty($data['username'])) {
                logger()->error('[OPSANY SSO] Invalid API response', ['data' => $data]);
                return $next($request);
            }

            $username = $data['username'];
            $email = $data['email'] ?? ($username . '@opsany.local');

            // 3️⃣ 已登录但用户不一致 → 强制切换账号
            if (Auth::check()) {
                $currentUser = Auth::user();

                if ($currentUser->email !== $email) {
                    logger()->info('[OPSANY SSO] User switched', [
                        'from' => $currentUser->email,
                        'to'   => $email,
                    ]);

                    Auth::logout();
                    $request->session()->invalidate();
                    $request->session()->regenerateToken();
                } else {
                    // 同一个用户，直接放行
                    return $next($request);
                }
            }

            // 4️⃣ 查找或创建 BookStack 用户
            $user = User::where('email', $email)->first();

            if (!$user) {
                $user = new User();
                $user->name = $username;
                $user->email = $email;
                $user->password = bcrypt(Str::random(32));

                // 生成唯一 slug（兼容 BookStack 约束）
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

                logger()->info('[OPSANY SSO] Created BookStack user', [
                    'email' => $email,
                    'slug'  => $slug,
                ]);
            }

            // 5️⃣ 登录 BookStack
            Auth::login($user);

            logger()->info('[OPSANY SSO] User logged in', [
                'username' => $username,
                'email'    => $email,
            ]);

        } catch (\Throwable $e) {
            logger()->error('[OPSANY SSO] Exception', [
                'error' => $e->getMessage(),
            ]);

            return $next($request);
        }

        return $next($request);
    }
}