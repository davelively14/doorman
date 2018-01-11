defmodule DoormanTest do
  use Doorman.ConnCase
  doctest Doorman

  @valid_email "joe@dirt.com"
  @valid_alternate_email "brandy@dirt.com"

  defmodule FakeSuccessRepo do
    def get_by(Fake, key) do
      case key do
        k when k in [[email: "joe@dirt.com"], [username: "joe_dirt"]]  ->
          %{
            username: "joe_dirt",
            email: "joe@dirt.com",
            hashed_password: Comeonin.Bcrypt.hashpwsalt("password")
          }
        _ ->
          nil
      end
    end

    def get_by(OtherFake, key) do
      case key do
        k when k in [[email: "brandy@dirt.com"], [username: "brandy_dirt"]] ->
          %{
            username: "brandy_dirt",
            email: "brandy@dirt.com",
            hashed_password: Comeonin.Bcrypt.hashpwsalt("password")
          }
        _ ->
          nil
      end
    end

    def get(Fake, id) do
      if id == 1 do
        %{
          username: "joe_dirt",
          email: "joe@dirt.com",
          hashed_password: Comeonin.Bcypt.hashpwsalt("password")
        }
      else
        nil
      end
    end
  end

  test "authenticate/1 takes valid keyword list and returns" do
    Mix.Config.persist([doorman: %{
       repo: FakeSuccessRepo,
       user_module: Fake,
       secure_with: Doorman.Auth.Bcrypt,
    }])

    assert Doorman.authenticate(username: "joe_dirt", password: "password").email == "joe@dirt.com"
    assert Doorman.authenticate(email: "joe@dirt.com", password: "password").email == "joe@dirt.com"
  end

  test "authenticate/1 takes invalid input and returns nil" do
    Mix.Config.persist([doorman: %{
       repo: FakeSuccessRepo,
       user_module: Fake,
       secure_with: Doorman.Auth.Bcrypt,
    }])

    assert Doorman.authenticate(email: "asdfkjkl", password: "password") == nil
    assert Doorman.authenticate(username: "asdfkjkl", password: "password") == nil
  end

  test "authenticate/1 takes valid input and invalid password and returns nil" do
    Mix.Config.persist([doorman: %{
       repo: FakeSuccessRepo,
       user_module: Fake,
       secure_with: Doorman.Auth.Bcrypt,
    }])

    assert Doorman.authenticate(email: @valid_email, password: "asdffdas") == nil
    assert Doorman.authenticate(username: "joe_dirt", password: "asdffdas") == nil
  end

  test "authenticate/2 takes an optional user module" do
    Mix.Config.persist([doorman: %{
       repo: FakeSuccessRepo,
       user_module: Fake,
       secure_with: Doorman.Auth.Bcrypt,
    }])

    assert Doorman.authenticate(OtherFake, username: "brandy_dirt", password: "password").email == "brandy@dirt.com"
    assert Doorman.authenticate(OtherFake, email: "brandy@dirt.com", password: "password").email == "brandy@dirt.com"
  end

  test "authenticate/3 takes valid email and valid password and returns true" do
    Mix.Config.persist([doorman: %{
       repo: FakeSuccessRepo,
       user_module: Fake,
       secure_with: Doorman.Auth.Bcrypt,
    }])

    assert Doorman.authenticate(@valid_email, "password").email == @valid_email
  end

  test "authenticate/3 takes invalid email and valid password and returns nil" do
    Mix.Config.persist([doorman: %{
       repo: FakeSuccessRepo,
       user_module: Fake,
       secure_with: Doorman.Auth.Bcrypt,
    }])

    assert Doorman.authenticate("fake", "password") == nil
  end

  test "authenticate/3 takes valid email and invalid password and returns nil" do
    Mix.Config.persist([doorman: %{
       repo: FakeSuccessRepo,
       user_module: Fake,
       secure_with: Doorman.Auth.Bcrypt,
    }])

    assert Doorman.authenticate(@valid_email, "wrong") == nil
  end

  test "authenticate/3 takes an optional user module" do
    Mix.Config.persist([doorman: %{
       repo: FakeSuccessRepo,
       user_module: Fake,
       secure_with: Doorman.Auth.Bcrypt,
    }])

    user = Doorman.authenticate(OtherFake, @valid_alternate_email, "password")
    assert user.email == @valid_alternate_email
  end

  test "login/1 returns true if the user is logged in" do
    conn = %Plug.Conn{}
    |> Plug.Conn.assign(:current_user, %{})

    assert Doorman.logged_in?(conn)
  end

  test "login/1 returns false if the current_user is nil" do
    conn = %Plug.Conn{}
    |> Plug.Conn.assign(:current_user, nil)

    refute Doorman.logged_in?(conn)
  end

  test "login/1 returns false if the current_user is not present" do
    conn = %Plug.Conn{}

    refute Doorman.logged_in?(conn)
  end
end
