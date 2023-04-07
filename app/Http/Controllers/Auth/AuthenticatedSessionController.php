<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Http\Requests\Auth\LoginRequest;
use App\Models\User;
use App\Notifications\Login;
use App\Providers\RouteServiceProvider;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\URL;
use Illuminate\View\View;

class AuthenticatedSessionController extends Controller
{
    /**
     * Display the login view.
     */
    public function create(): View
    {
        return view('auth.login');
    }

    /**
     * Handle an incoming authentication request.
     */
    public function store()
    {
        request()->validate(['email' => 'required']);

        $user = User::where(['email' => request('email')])->first();

        if (! $user) {
            return back()->withErrors(['email' => 'No matching account found.']);
        }

        $link = URL::temporarySignedRoute(
            'login.token',
            now()->addHour(),
            ['user' => $user->id]
        );

        $user->notify(new Login($link));

        return back()->with(['status' => 'Please check your email for a login link!']);

    }

    /**
     * Login the user.
     */
    public function loginViaToken(User $user): RedirectResponse
    {
        Auth::login($user);

        request()->session()->regenerate();

        return redirect(RouteServiceProvider::HOME);
    }

    /**
     * Destroy an authenticated session.
     */
    public function destroy(Request $request): RedirectResponse
    {
        Auth::guard('web')->logout();

        $request->session()->invalidate();

        $request->session()->regenerateToken();

        return redirect('/');
    }
}
