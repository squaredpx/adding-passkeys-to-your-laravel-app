<?php

use App\Http\Controllers\Api\PasskeyController;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

Route::middleware('auth:sanctum')->get('/passkeys/register', [PasskeyController::class, 'registerOptions']);

Route::get('/passkeys/authenticate', [PasskeyController::class, 'authenticateOptions']);
