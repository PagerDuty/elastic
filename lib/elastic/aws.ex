defmodule Elastic.AWS do
  require Logger
  @moduledoc false
  def enabled? do
    Logger.info("Elastic settings: #{Kernel.inspect(settings())}")
    settings()[:enabled]
  end

  def sign_url(method, url, headers, body) do
    AWSAuth.sign_url(
      settings().access_key_id,
      settings().secret_access_key,
      to_string(method),
      url,
      settings().region,
      "es",
      process_headers(method, headers),
      DateTime.utc_now |> DateTime.to_naive,
      body
    )
  end

  def sign_authorization_headers(method, url, headers, body) do
    Logger.info("Elastic settings: #{Kernel.inspect(settings())}")
    uri = URI.parse(url)
    request_time = DateTime.utc_now |> DateTime.to_naive
    time_header = request_time |> AWSAuth.Utils.format_time
    content_header = AWSAuth.Utils.hash_sha256(body)

    headers = headers |> Keyword.put(:"X-Amz-Date", time_header)
    |> Keyword.put(:host, uri.host)
    |> Keyword.put(:"x-amz-content-sha256", content_header)
    Logger.info("Headers before signing: #{Kernel.inspect(headers)}")
    signed_header = AWSAuth.sign_authorization_header(
      settings.access_key_id,
      settings.secret_access_key,
      to_string(method),
      url,
      settings.region,
      "es",
      process_headers(method, headers),
      body,
      request_time
    )
    headers |> Keyword.put(:Authorization, signed_header)
  end

  # DELETE requests do not support headers
  defp process_headers(:delete, _), do: %{}

  defp process_headers(_method, headers) do
    for {k, v} <- headers,
      into: %{},
      do: {to_string(k), to_string(v)}
  end

  defp settings do
    Application.get_env(:elastic, :aws)
  end
end
