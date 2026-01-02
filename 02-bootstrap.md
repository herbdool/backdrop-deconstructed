# The Bootstrap Process

So George's request for `/about-us` has been handed to Backdrop, and `index.php` is ready to bootstrap Backdrop. What does that mean?

## A quick summary

At a code level, we're talking about the [`backdrop_bootstrap`](https://docs.backdropcms.org/api/backdrop/core%21includes%21bootstrap.inc/function/backdrop_bootstrap/1) function, which lets you pass in a parameter to tell it which level of bootstrap you need. In almost all cases, we want a "full" bootstrap, which usually means "this is a regular page request, nothing weird, so just give me everything."

What is "everything"? I'm glad you asked. All of the possible values for the parameter for `backdrop_bootstrap()` are listed below. Note that they are run sequentially, meaning if you call it with `BACKDROP_BOOTSTRAP_CONFIGURATION` then it will only do that one (#1), but if you call it with `BACKDROP_BOOTSTRAP_SESSION` then it will do that one (#5) and all of the ones before it (#1-4). And since `BACKDROP_BOOTSTRAP_FULL` is last, calling it gives you everything in this list.

1. `BACKDROP_BOOTSTRAP_CONFIGURATION`: Set up some configuration
2. `BACKDROP_BOOTSTRAP_PAGE_CACHE`: Try to serve the page from the cache (in which case the rest of these steps don't run)
3. `BACKDROP_BOOTSTRAP_DATABASE`: Initialize the database connection
4. `BACKDROP_BOOTSTRAP_VARIABLES`: Load variables from the `variables` table
5. `BACKDROP_BOOTSTRAP_SESSION`: Initialize the user's session
6. `BACKDROP_BOOTSTRAP_PAGE_HEADER`: Set HTTP headers to prepare for a page response
7. `BACKDROP_BOOTSTRAP_LANGUAGE`: Initialize language types for multilingual sites
8. `BACKDROP_BOOTSTRAP_FULL`: Includes a bunch of other files and does some other miscellaneous setup.

Each of these are defined in more detail below.

## 1. `BACKDROP_BOOTSTRAP_CONFIGURATION`

This guy just calls [`_backdrop_bootstrap_configuration()`](https://docs.backdropcms.org/api/backdrop/core%21includes%21bootstrap.inc/function/_backdrop_bootstrap_configuration/1), which in turn does the following:

### Sets error and exception handlers.

```php
set_error_handler('_backdrop_error_handler');
set_exception_handler('_backdrop_exception_handler');
```

These lines set a custom error handler ([`_backdrop_error_handler()`](https://docs.backdropcms.org/api/backdrop/core%21includes%21bootstrap.inc/function/_backdrop_error_handler/1)) and a custom exception handler ([`_backdrop_exception_handler`](https://docs.backdropcms.org/api/backdrop/core%21includes%21bootstrap.inc/function/_backdrop_exception_handler/1)) respectively. That means that those functions are called when Backdrop encounters a PHP error or exception.

These functions each go a few levels deep, but all they're really doing is attempting to log any errors or exceptions that may occur, and then throw a `500 Service unavailable` response.

### Initializes the PHP environment

```php
backdrop_environment_initialize()
```

The [`backdrop_environment_initialize()`](https://docs.backdropcms.org/api/backdrop/core%21includes%21bootstrap.inc/function/backdrop_environment_initialize/1) function called here does a lot, most of which isn't very interesting. For example: 

- It tinkers with the global `$_SERVER` array a little bit.
- It sets the configuration for error reporting
- It sets some session configuration using `ini_set()`

Boring.

That said, it does have this nugget:

```php
$_GET ['q'] = request_path();
```

It might not look like much, but this is what makes Clean URLs work. We always need `$_GET['q']` to be set to the current path because `$_GET['q']` is used all over the place. If you have Clean URLs disabled, then that happens by default, because your URLs look like `yoursite.com/?q=about-us`. So the line of code above will call [`request_path()`](https://docs.backdropcms.org/api/backdrop/core%21includes%21bootstrap.inc/function/request_path/1), which sees that `$_GET['q']` already exists, and returns it directly. 

But if you have Clean URLs enabled (you do, right?), and your URLs look like `yoursite.com/about-us`, then `$_GET['q']` is empty by default, and that just won't do. To fix that, it gets populated with the value of [`request_path()`](https://docs.backdropcms.org/api/backdrop/core%21includes%21bootstrap.inc/function/request_path/1), which basically just cleans up the result of `$_SERVER['REQUEST_URI']` (i.e., removes query strings as well as script filenames such as `index.php` or `cron.php`) and returns that.

### Starts a timer

```php
timer_start('page');
```

This is actually pretty nifty. Backdrop has a global `$timers` variable that many people don't know about. 

Here, a timer is started so that the time it takes to render the page can be measured.

### Initializes some critical settings

```php
backdrop_settings_initialize();
```

The [`backdrop_settings_initialize()`](https://docs.backdropcms.org/api/backdrop/core%21includes%21bootstrap.inc/function/backdrop_settings_initialize/1) function is super important, for at least 3 reasons:

1. It includes the all-important `settings.php` file which contains our database connection info (which isn't used yet), among other things.
2. It creates many of our favorite global variables, such as `$cookie_domain`, `$conf`, `$is_https`, and more!
3. It sets the name of the session cookie. PHP, by default, stores the session id in a cookie named PHPSESSID. Backdrop instead builds a cookie name that starts with the substring SESS and ends with a hash of the cookie domain.

### Load configuration

```php
$config_storage = config_get_config_storage('active');
```

By default, configuration is stored in JSON files in a config directory. It loads this directory so it can be accessed. There is also an option of storing configuration in the database, which means this line also has to bootstrap the database if needed.

And that's the end of the CONFIGURATION bootstrap. 1 down, 7 to go!

## 2. `BACKDROP_BOOTSTRAP_PAGE_CACHE`

When bootstrapping the page cache, everything happens inside [`_backdrop_bootstrap_page_cache()`](https://docs.backdropcms.org/api/backdrop/core%21includes%21bootstrap.inc/function/_backdrop_bootstrap_page_cache/1) which does a lot of work.

### Includes cache.inc and any custom cache backends

```php
require_once BACKDROP_ROOT . '/core/includes/cache.inc';
foreach (settings_get('cache_backends', array()) as $include) {
  require_once BACKDROP_ROOT . '/' . $include;
}
```

This bit of fanciness allows us to specify our own cache backend(s) instead of using Backdrop's database cache. 

This is most commonly used to support memcache, but someone could really go to town with this if they wanted, just by specifying (in the `$conf` array in `settings.php`) an include file to use (such as `memcache.inc`) for whatever cache backend they're wanting to use.

### Checks to see if cache is enabled

```php
// Check for a cache mode force from settings.php.
if (settings_get('page_cache_without_database')) {
  $cache_enabled = TRUE;
}
else {
  backdrop_bootstrap(BACKDROP_BOOTSTRAP_VARIABLES, FALSE);
  $cache_enabled = settings_get('cache');
}
```

You'll note that the first line there gives you a way to enable cache from `settings.php` directly. This speeds things up because that way it doesn't need to bootstrap `BACKDROP_BOOTSTRAP_VARIABLES` (i.e., load all of the variables from the DB table) which would also force it to bootstrap `BACKDROP_BOOTSTRAP_DATABASE`, which is a requirement for fetching the variables from the database, all just to see if the cache is enabled.

So assuming you don't have `$conf['page_cache_without_database'] = TRUE` in your `settings.php` file, then we will be bootstrapping the variables here, which in turn bootstraps the database. Both of those will be talked about in more info in a minute.

### Blocks any IP blacklisted users

**NOTE: Removed from Backdrop


### Checks to see if there's a session cookie

```php
if (!isset($_COOKIE [session_name()]) && $cache_enabled) {
  ...fetch and return cached response if there is one...
}
```

It only returns a cached response (assuming one exists to return) if the user doesn't have a valid session cookie. This is a way of ensuring that only anonymous users see cached pages, and authenticated users don't. (What's that? [You want authenticated users to see cached pages too](https://ohthehugemanatee.org/blog/2014/06/09/authenticated-user-caching-in-drupal/)?)


What's inside that "fetch and return cached response" block? Lots of stuff!

### Populates the global $user object

```php
$user = backdrop_anonymous_user();
```

The [`backdrop_anonymous\_user()`](https://docs.backdropcms.org/api/backdrop/core%21includes%21bootstrap.inc/function/backdrop_anonymous_user/1) function just creates an empty user object with a `uid` of 0.  We're creating it here just because it may need to be used later on down the line, such as in some `hook_boot()` implementation, and also because its timestamp will be checked and possibly logged.

### Checks to see if the page is already cached

```php
$cache = backdrop_page_get_cache();
```

The [`backdrop_page_get_cache()`](https://docs.backdropcms.org/api/backdrop/core%21includes%21bootstrap.inc/function/backdrop_page_get_cache/1) function is actually simpler than you'd think. It just checks to see if the page is cacheable (i.e., if the request method is either `GET` or `HEAD`, as told in [`backdrop_page_is_cacheable()`](https://docs.backdropcms.org/api/backdrop/core%21includes%21bootstrap.inc/function/backdrop_page_is_cacheable/1)), and if so, it runs `cache_get()` with the current URL against the `cache_page` database table, to fetch the cache, if there is one.

An interesting situation occurs in a single sign on scenario. When the user is logged into the master site, but is visiting a particular Backdrop site in the site family for the first time, that user will not have a session cookie on that particular site. This situation is one of the major use cases for `hook_boot()`, which is invoked immediately prior to trying to serve the cached page.

```
      if (settings_get('page_cache_invoke_hooks', TRUE)) {
        bootstrap_invoke_all('boot');
      }
```

Your particular implementation of hook_boot() can test for a shared cookie (or other condition like a header injected by a proxy), and then force Backdrop to continue with a full bootstrap. See the implementation in the bakery contrib module for a good example of this. hook_boot() is also where a module can block or ban users before the whole page is served. An example of this is the ban_ip module, something which was fomerly included in Drupal 7 core with:

```php
drupal_block_denied(ip_address());
```
An interesting thing to note here is that the [`ip_address()`](https://docs.backdropcms.org/api/backdrop/core%21includes%21bootstrap.inc/function/ip_address/1) function is super useful. On a normal site it just returns regular old `$_SERVER['REMOTE_ADDR']`, but if you're using some sort of reverse proxy in front of Backdrop (meaning `$_SERVER['REMOTE_ADDR']` will always be the same), then it fetches the user's IP from the (configurable) HTTP header. Pretty awesome. 

We'll take a deeper look at this function once we get to the module chapter.

### Serves the response from that cache

If `$cache` from the previous section isn't empty, then we have officially found ourselves a valid page cache for the current page, and we can return it and shut down. This block of code does a few things:

- Sets the page title using [`backdrop_set_title()`](https://docs.backdropcms.org/api/backdrop/core%21includes%21bootstrap.inc/function/backdrop_set_title/1)
- Sets a HTTP header: `X-Backdrop-Cache: HIT`
- Sets PHP's default timezone to the site's default timezone (from `variable_get('date_default_timezone')`)
- Runs all implementations of `hook_boot()`, if the `page_cache_invoke_hooks` variable isn't set to FALSE.
- Serves the page from cache, using [`backdrop_serve_page_from_cache($cache)`](https://docs.backdropcms.org/api/backdrop/core%21includes%21bootstrap.inc/function/backdrop_serve_page_from_cache/1), which is scary looking but basically just adds some headers and prints the cache data (i.e., the page body).
- Runs all implementations of `hook_exit()`, if the `page_cache_invoke_hooks` variable isn't set to FALSE.

And FINALLY, once all of that is complete, it runs `exit;` and we're done, assuming we got this far. 

Otherwise, it doesn't do any of the above, and just sets the `X-Backdrop-Cache: MISS` header.

Whew. That's a lot of stuff. Luckily, the next section is easier.

## 3. `BACKDROP_BOOTSTRAP_DATABASE`

We're not going to get super in the weeds with everything Backdrop does with the database here, since that deserves its own chapter, but here's an overview of the parts that happen while bootstrapping, within the [`_backdrop_bootstrap_database()`](https://docs.backdropcms.org/api/backdrop/core%21includes%21bootstrap.inc/function/_backdrop_bootstrap_database/1) function.

### Checks to see if we have a database configured

```php
if (empty($GLOBALS ['databases']) && !backdrop_installation_attempted()) {
  include_once BACKDROP_ROOT . '/core/includes/install.inc';
  install_goto('install.php');
}
```

Nothing fancy. If we don't have anything in `$GLOBALS ['databases']` and we haven't already started the installation process, then we get booted to `/install.php` since Backdrop is assuming we need to install the site.

### Includes the `database.inc` file

This beautiful beautiful [`database.inc`](https://docs.backdropcms.org/api/backdrop/core%21includes%21database%21database.inc/1) file includes all of the database abstraction functions that we know and love, such as `db_query()` and `db_select()` and `db_update()`. 

It also holds the base `Database` and `DatabaseConnection` and `DatabaseTransaction` classes (among a bunch of others).

It's a 3000+ line file, so it's out of scope for a discussion on bootstrapping, and we'll get back to "How Backdrop Does Databases" in a later chapter.

### Registers autoload functions for classes and interfaces

```php
spl_autoload_register('backdrop_autoload');
```

This is just a tricky way of ensuring that a class or interface actually exists, when we try to autoload one. [`backdrop_autoload()`](https://docs.backdropcms.org/api/backdrop/core%21includes%21bootstrap.inc/function/backdrop_autoload/1) calls [`hook_autoload_info()`](https://docs.backdropcms.org/api/backdrop/core%21modules%21system%21system.api.php/function/hook_autoload_info/1), which loads all classes and interfaces defined in that hook across all enabled modules. 

If it finds the class or interface, it will `require_once` the file that contains that class or interface and return `TRUE`. Otherwise, it just returns `FALSE` so Backdrop knows that somebody screwed the pooch and we're looking for a class or interface that doesn't exist.

So, in English, it's saying "*Ok, it looks like you're trying to autoload a class or an interface, so I'll figure out which file it's in by checking the cache or the registry database table, and then include that file, if I can find it.*"

## 4. `BACKDROP_BOOTSTRAP_VARIABLES`

This one just calls [`_backdrop_bootstrap_variables()`](https://docs.backdropcms.org/api/backdrop/core%21includes%21bootstrap.inc/function/_backdrop_bootstrap_variables/1), which actually does a good bit more than just including the variables from the variables table. 

Here's what it does:

### Initializes the locking system

```php
require_once BACKDROP_ROOT . '/' . settings_get('lock_inc', 'core/includes/lock.inc');
lock_initialize();
```

Backdrop's locking system allows us to create arbitrary locks on certain operations, to prevent race conditions and other bad things. If you're interested to read more about this, there is a very good [API page about it](https://docs.backdropcms.org/api/backdrop/core%21includes%21lock.inc/group/lock/1).

The two lines of code here don't actually acquire any locks, they just initialize the locking system so that later code can use it. In fact, it's actually used in the very next section, which is why it's initialized in this seemingly unrelated phase of the bootstrap process.

### Load variables from the database

**NOTE: this is deprecated but still included to provide some backwards-compatibility with Drupal 7's variables.**

```php
global $conf;
$conf = variable_initialize(isset($conf) ? $conf : array());
```

The [`variable_initialize()`](https://docs.backdropcms.org/api/backdrop/core%21includes%21bootstrap.inc/function/variable_initialize/1) function basically just returns everything from the `variables` database table, which in this case adds it all to the global `$conf` array, so that we can `variable_get()` things from it later.

But there are a few important details:

1. It tries to load from the cache first, by looking for the `variables` cache ID in the `cache_bootstrap` table.
2. Assuming the cache failed, it tries to acquire a lock to avoid a stampede if a ton of requests are all trying to grab the `variables` table at the same time. 
3. Once it has the lock acquired, it grabs everything from the `variables` table.
4. Then it caches all of that, so that step 1 won't fail next time.
5. Finally, it releases the lock.

### Load states from the persistent state table



### Load all "bootstrap mode" modules

```php
require_once BACKDROP_ROOT . '/core/includes/module.inc';
module_load_all(TRUE);
```

Note that this may seem scary (OH MY GOD we're loading every single module just to bootstrap the variables!) but it's not. That `TRUE` is a big deal, because that tells Backdrop to only load the "bootstrap" modules. A "bootstrap" module is a module that has the `bootstrap` column in the `system` table set to 1 for it. 

On the typical Backdrop site, this will only be a handful of modules that are specifically required this early in the bootstrap, like the Syslog module or the System module, or some contrib modules like Redirect or Variable.

### Sanitize the `destination` URL parameter

Here's another one that you wouldn't expect to happen as part of bootstrapping variables. 

The `$_GET['destination']` parameter needs to be protected against open redirect attacks leading to other domains. So what we do here is to check to see if it's set to an external URL, and if so, we unset it. 

The reason we have to wait for the variables bootstrap for this is that we need to call the [`url_is_external()`](https://docs.backdropcms.org/api/backdrop/core%21includes%21common.inc/function/url_is_external/1) function to check the destination URL, and that function calls [`backdrop_strip_dangerous_protocols()`](https://docs.backdropcms.org/api/backdrop/core%21includes%21common.inc/function/backdrop_strip_dangerous_protocols/1) which has a variable to store the list of allowed protocols.

## 5. `BACKDROP_BOOTSTRAP_SESSION`

Bootstrapping the session means requiring the `session.inc` file and then running [`backdrop_session_initialize()`](https://docs.backdropcms.org/api/backdrop/core%21includes%21session.inc/function/backdrop_session_initialize/1), which is a pretty fun function.

### Register custom session handlers

The first thing that happens here is that Backdrop registers custom session handlers with PHP:

```php
session_set_save_handler('_backdrop_session_open', '_backdrop_session_close', 
  '_backdrop_session_read', '_backdrop_session_write', 
  '_backdrop_session_destroy', '_backdrop_session_garbage_collection');
```

**NOTE: this is now handled with a session class as required by PHP 8.4 and higher.**

If you've never seen the [`session_set_save_handler()`](http://php.net/session_set_save_handler) PHP function before, it just allows you to set your own custom session storage functions, so that you can have full control over what happens when sessions are opened, closed, read, written, destroyed, or garbage collected. As you can see above, Backdrop implements its own handlers for all 6 of those.

What does Backdrop actually do in those 6 handler functions? 

- `_backdrop_session_open()` and `_backdrop_session_close()` both literally just `return TRUE;`.
- `_backdrop_session_read()` fetches the session from the `sessions` table, and does a join on the `users` table to include the user data along with it.
- `_backdrop_session_write()` checks to see if the session has been updated in the current page request or more than 180 seconds have passed since the last update, and if so, it gathers up session data and drops it into the `sessions` table with a `db_merge()`.
- `_backdrop_session_destroy()` just deletes the appropriate row from the `sessions` DB table, sets the global `$user` object to be the anonymous user, and deletes cookies.
- `_backdrop_session_garbage_collection()` deletes all sessions from the `sessions` table that are older than whatever the max lifetime is set to in PHP (i.e., whatever `session.gc_maxlifetime` is set to).

### If we already have a session cookie, then start the session

We then check to see if there's a valid session cookie in `$_COOKIE[session_name()]`, and if so, we run the [`backdrop_session_start()`](https://docs.backdropcms.org/api/backdrop/core%21includes%21session.inc/function/backdrop_session_start/1). If you're a PHP developer and you just want to know where `session_start()` happens, then you've found it.

That's basically all that `backdrop_session_start()` does, besides making sure that we're not a command line client and we haven't already started the session.

### Disable page cache for this request

Remember back in the `BACKDROP_BOOTSTRAP_PAGE_CACHE` section where I said that authenticated users don't get cached pages (unless you use something outside of Backdrop core)? This is the part that makes that happen.

```php
if (!empty($user->uid) || !empty($_SESSION)) {
  backdrop_page_is_cacheable(FALSE);
}
```

So if we have a session or a nonzero user ID, then we mark this page as uncacheable, because we may be seeing user-specific data on it which we don't want anyone else to see.

### If we don't already have a session cookie, lazily start one

This part's tricky. Backdrop lazily starts sessions at the end of the request, so all the bootstrap process has to do is create a session ID and tell $_COOKIE about it, so that it can get picked up at the end.

```php
session_id(backdrop_random_key());
```

I won't go in detail here since we're talking about the bootstrap, but at the end of the request, `backdrop_page_footer()` or `backdrop_exit()` (depending on which one is responsible for closing this particular request) will call [`backdrop_session_commit()`](https://docs.backdropcms.org/api/backdrop/core%21includes%21session.inc/function/backdrop_session_commit/1), which checks to see if there's anything in $_SESSION that we need to save to the database, and will run `backdrop_session_start()` if so.

### Sets PHP's default timezone from the user's timezone

```php
date_default_timezone_set(backdrop_get_user_timezone());
```

You may remember that the cache bootstrap above was responsible for setting the timezone for cached pages. This is where the timezone gets set for uncached pages. 

The [`backdrop_get_user_timezone()`](https://docs.backdropcms.org/api/backdrop/core%21includes%21bootstrap.inc/function/backdrop_get_user_timezone/1) is very simple. It just checks to see if user-configurable timezones are enabled and the user has one set, and uses that if so, otherwise it falls back to the site's default timezone setting.

## 6. `BACKDROP_BOOTSTRAP_PAGE_HEADER`

This is probably the simplest of the bootstrap levels. It does 2 very simple things in the [`_backdrop_bootstrap_page_header()`](https://docs.backdropcms.org/api/backdrop/core%21includes%21bootstrap.inc/function/_backdrop_bootstrap_page_header/1) function.

### Invokes hook_boot()

```php
bootstrap_invoke_all('boot');
```

If you've ever wondered how much of the bootstrap process has to complete before you can be guaranteed that hook_boot will run, there's your answer. Remember that for cached pages, it will have already run back in the cache bootstrap, but for uncached pages, this is where it happens.

### Sends initial HTTP headers 

There's a little bit of a call stack here. `backdrop_page_header()` calls `backdrop_send_headers()` which calls `backdrop_get_http_header()` to finally fetch the headers that it needs to send.

Note that in this run, it just sends a couple default headers (`Expires` and `Cache-Control`), but the interesting part is that static caches are used throughout, and anything can call [`backdrop_add_http_header()`](https://docs.backdropcms.org/api/backdrop/core%21includes%21bootstrap.inc/function/backdrop_add_http_header/1) later on down the line, which will also call `backdrop_send_headers()`. This allows you to append or replace existing headers before they actually get sent anywhere.


## 7. `BACKDROP_BOOTSTRAP_LANGUAGE`

In this level, the [`backdrop_language_initialize()`](https://docs.backdropcms.org/api/backdrop/core%21includes%21bootstrap.inc/function/backdrop_language_initialize/1) function is called. This function only really does anything if we're talking about a multilingual site. It checks `language_multilingual()` which just returns `TRUE` if the list of languages is greater than 1, and false otherwise.

If it's not a multilingual site, it cuts out then.

If it is a multilingual site, then it initializes the system using `language_initialize()` for each of the language types that been configured, and then runs all `hook_language_init()` implementations.

This is a good time to note that the language system is complicated and confusing, with a web of "language types" (such as `LANGUAGE_TYPE_INTERFACE` and `LANGUAGE_TYPE_CONTENT`) and "language providers", and of course actual languages. It deserves a chapter of its own, so I'm not going to go into any more detail here.

## 8. `BACKDROP_BOOTSTRAP_FULL`

And we have landed. Now that we already have the building blocks like a database and a session and configuration, we can add All Of The Other Things. We require the common.inc file and its [`_backdrop_bootstrap_full()`](https://docs.backdropcms.org/api/backdrop/core%21includes%21common.inc/function/_backdrop_bootstrap_full/1) function does just that.

### Requires a ton of files

```php
require_once BACKDROP_ROOT . '/' . settings_get('path_inc', 'core/includes/path.inc');
require_once BACKDROP_ROOT . '/core/includes/theme.inc';
require_once BACKDROP_ROOT . '/core/includes/pager.inc';
require_once BACKDROP_ROOT . '/' . settings_get('menu_inc', 'core/includes/menu.inc');
require_once BACKDROP_ROOT . '/core/includes/tablesort.inc';
require_once BACKDROP_ROOT . '/core/includes/file.inc';
require_once BACKDROP_ROOT . '/core/includes/unicode.inc';
require_once BACKDROP_ROOT . '/core/includes/image.inc';
require_once BACKDROP_ROOT . '/core/includes/form.inc';
require_once BACKDROP_ROOT . '/core/includes/mail.inc';
require_once BACKDROP_ROOT . '/core/includes/actions.inc';
require_once BACKDROP_ROOT . '/core/includes/ajax.inc';
require_once BACKDROP_ROOT . '/core/includes/token.inc';
require_once BACKDROP_ROOT . '/core/includes/errors.inc';
```

All that stuff that we haven't needed yet but may need after this, we require here, just in case. That way, we're not having to load `ajax.inc` on the fly if we happen to be using AJAX later, or `mail.inc` on the fly if we happen to be sending an email.


### Load all enabled modules

The [`module_load_all()`](https://docs.backdropcms.org/api/backdrop/core%21includes%21module.inc/function/module_load_all/1) does exactly what you'd expect - grabs the name of every enabled module using `module_list()` and then runs `backdrop_load()` on it to load it. There's also a static cache in this function so that it only runs once per request.

### Registers stream wrappers

The [`file_get_stream_wrappers()`](https://docs.backdropcms.org/api/backdrop/core%21includes%21file.inc/function/file_get_stream_wrappers/1) has a lot of meat to it, but it's all details around a fairly simple task.

At a high level, it's grabbing all stream wrappers using `hook_stream_wrappers()`, allowing the chance to alter them using `hook_stream_wrappers_alter()`, and then registering (or overriding) each of them using `stream_wrapper_register()`, which is a plain old PHP function. It then sticks the result in a static cache so that it only runs all of this once per request.

### Initializes the path

The [`backdrop_path_initialize()`](https://docs.backdropcms.org/api/backdrop/core%21includes%21path.inc/function/backdrop_path_initialize/1) function is called which just makes sure that `$_GET['q']` is setup (if it's not, then it sets it to the frontpage), and then runs it through [`backdrop_get_normal_path()`](https://docs.backdropcms.org/api/backdrop/core%21includes%21path.inc/function/backdrop_get_normal_path/1) to see if it's a path alias, and if so, replace it with the internal path. 

This also gives modules a chance to alter the inbound URL. Before `backdrop_get_normal_path()` returns the path, it calls all implementations of `hook_url_inbound_alter()` to do just that.

### Sets and initializes the site theme

```php
menu_set_custom_theme();
backdrop_theme_initialize();
```

These two fairly innocent looking functions are NOT messing around. 

The purpose of [`menu_set_custom_theme()`](https://docs.backdropcms.org/api/backdrop/core%21includes%21menu.inc/function/menu_set_custom_theme/1) is to allow modules or theme callbacks to dynamically set the theme that should be used to render the current page. To do this, it  calls [`menu_get_custom_theme(TRUE)`](https://docs.backdropcms.org/api/backdrop/core%21includes%21menu.inc/function/menu_get_custom_theme/1), which is a bit scary looking, but doesn't do anything important besides that and saving the result to a static cache.

After that, the [`backdrop_theme_initialize()`](https://docs.backdropcms.org/api/backdrop/core%21includes%21theme.inc/function/backdrop_theme_initialize/1) comes along and goes to town.

First, it just loads all themes using [`list_themes()`](https://docs.backdropcms.org/api/backdrop/core%21includes%21theme.inc/function/list_themes/1), which is where the `.info` file for each theme gets parsed and the lists of CSS files, JS files, regions, etc., get populated.

Secondly, it tries to find the theme to use by checking to see if the user has a custom theme set, and if not, falling back to the `theme_default` variable.

```php
$theme = !empty($user->theme) && backdrop_theme_access($user->theme) ? 
  $user->theme : variable_get('theme_default', 'bartik');
```

Then it checks to see if a different custom theme was chosen on the fly in the previous step (the `menu_set_custom_theme()` function), by running `menu_get_custom_theme()` (remember that static cache). If there was a custom theme returned, then it uses that, otherwise it keeps the default theme.

```php
$custom_theme = menu_get_custom_theme();
$theme = !empty($custom_theme) ? $custom_theme : $theme;
```

Once it has firmly decided on what dang theme is going to render the dang page, it can move on to building a list of base themes or ancestor themes.

```php
$base_theme = array();
$ancestor = $theme;
while ($ancestor && isset($themes [$ancestor]->base_theme)) {
  $ancestor = $themes [$ancestor]->base_theme;
  $base_theme [] = $themes [$ancestor];
}
```

It needs that list because it needs to initialize any ancestor themes along with the main theme, so that theme inheritance can work. So then it runs [`_backdrop_theme_initialize`](https://docs.backdropcms.org/api/backdrop/core%21includes%21theme.inc/function/_backdrop_theme_initialize/1) on each of them, which adds the necessary CSS and JS, and then initializes the correct theme engine, if needed.

After that, it resets the `backdrop_alter` cache, because themes can have alter hooks, and we wouldn't want to ignore them becuase we had already built the cache by now.

```
backdrop_static_reset('backdrop_alter');
```

And finally, it adds some info to JS about the theme that's being used, so that if an AJAX request comes along later, it will know to use the same theme.

```php
$setting['ajaxPageState'] = array(
  'theme' => $theme_key,
  'theme_token' => backdrop_get_token($theme_key),
);
backdrop_add_js($setting, 'setting');
```

### A couple other miscellaneous setup tasks

- Detects string handling method using `unicode_check()`.
- Undoes magic quotes using `fix_gpc_magic()`.
- Ensures `mt_rand` is reseeded for security.
- Runs all implementations of `hook_init()` at the very end.

## Conclusion

That's it. That's the entire bootstrap process. There are a lot of places that deserve some more depth, and we'll get there, but you should be feeling like you have a fairly good understanding of where and when things get set up while bootstrapping.

Keep in mind this is only a small part of the page load process. Most of the really heavy lifting happens after this, so keep reading!
