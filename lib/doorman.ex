defmodule Doorman do
  @moduledoc """
  Provides authentication helpers that take advantage of the options configured
  in your config files.
  """

  @doc """
  Authenticates a user by passing a user's unique field and password. Returns
  the user if the user is found and the password is correct, otherwise nil.

  Requires `user_module`, `secure_with`, and `repo` to be configured via
  `Mix.Config`. See [README.md] for an example.

  ```
  Doorman.authenticate(username: "joe_dirt", password: "brandyr00lz")
  Doorman.authenticate(email: "joe_dirt", password: "brandyr00lz")
  Doorman.authenticate("joe@dirt.com", "brandyr00lz")
  ```

  If you want to authenticate other modules, you can pass in the module directly.

  ```
  Doorman.authenticate(Customer, username: "joe_dirt", password: "brandyr00lz")
  Doorman.authenticate(Customer, email: "joe_dirt", password: "brandyr00lz")
  Doorman.authenticate(Customer, "brandy@dirt.com", "super-password")
  ```
  """
  def authenticate(opts) when is_list(opts), do: authenticate(get_user_module(), opts)
  def authenticate(user_module, opts) when is_list(opts) do
    key_to_find =
      opts
      |> Keyword.delete(:password)
      |> Keyword.keys
      |> List.first

    user = repo_module().get_by(user_module, Keyword.new([{key_to_find, opts[key_to_find]}]))
    cond do
      user && authenticate_user(user, Keyword.get(opts, :password)) -> user
      user -> nil
      true ->
        auth_module().dummy_checkpw()
        nil
    end
  end
  def authenticate(user_module \\ nil, email, password) do
    authenticate(user_module || get_user_module(), email: email, password: password)
  end

  @doc """
  Authenticates a user. Returns true if the user's password and the given
  password match based on the strategy configured, otherwise false.

  Use `authenticate/2` if if you would to authenticate by email and password.

  Requires `user_module`, `secure_with`, and `repo` to be configured via
  `Mix.Config`. See [README.md] for an example.

  ```
  user = Myapp.Repo.get(Myapp.User, 1)
  Doorman.authenticate_user(user, "brandyr00lz")
  ```
  """
  def authenticate_user(user, password) do
    auth_module().authenticate(user, password)
  end

  @doc """
  Returns true if passed in `conn`s `assigns` has a non-nil `:current_user`,
  otherwise returns false.

  Make sure your pipeline uses a login plug to fetch the current user for this
  function to work correctly..
  """
  def logged_in?(conn) do
    conn.assigns[:current_user] != nil
  end

  defp repo_module do
    get_module(:repo)
  end

  defp get_user_module do
    get_module(:user_module)
  end

  defp auth_module do
    get_module(:secure_with)
  end

  defp get_module(name) do
    case Application.get_env(:doorman, name) do
      nil ->
        raise """
        You must add `#{Atom.to_string(name)}` to `doorman` in your config

        Here is an example configuration:

          config :doorman,
            repo: MyApp.Repo,
            secure_with: Doorman.Auth.Bcrypt,
            user_module: MyApp.User
        """
      module -> module
    end
  end
end
