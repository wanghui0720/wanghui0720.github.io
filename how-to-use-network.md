#chromium network

chromium的network库除了blink的web_url_loader 使用，还提供了一套接口方便其他使用者使用， 本篇文章我们讲解以下 network stack的使用，以及network stack 在chromium 中的使用。


###  network stack的使用


* 首先创建一个URLRequestContext
   URLRequestContext用来创建URLRequest

		net::URLRequestContextBuilder builder;
		url_request_context = builder.Build();

* 创建一个delegate用来接收request返回的数据
URLRequest 构造函数需要一个 URLRequest::Delegate 我们是通过这个delegate来回调接收数据的。
   看以下URLRequest::Delegate

	 	 class NET_EXPORT Delegate {
	  	 public:

			...

		    virtual void OnResponseStarted(URLRequest* request, int net_error);
		    virtual void OnReadCompleted(URLRequest* request, int bytes_read) = 0;

		   protected:
		    virtual ~Delegate() {}
		  };
   重写OnReadCompleted来获取数据。

		class MyDelegate : public URLRequest::Delegate	{
			void OnReadCompleted(URLRequest* request, int bytes_read) {
				  while (bytes_read > 0) {
				    bytes_read = request_->Read(buffer_.get(), kBufferSize);
				  }

				  if (bytes_read != ERR_IO_PENDING) {
				    status_ = URLRequestStatus::FromError(bytes_read);
				    //错误处理
				  }
			}
			void UrlDownloader::OnResponseStarted(net::URLRequest* request, int net_error) {
			    bytes_read = request_->Read(buffer_.get(), kBufferSize); //读取第一个trunk  header
			    OnReadCompleted(request_.get(), bytes_read);
			}
		}

* 然后通过URLReqeustContext创建一个URLRequest

		net::URLRequest* request = url_request_context.CreateRequest(url, DEFAULT_PRIORITY, delegate);
		request->Start();





  下面我们介绍一下URLRquest 是怎样请求资源的。

### network stack 介绍

<h4 id="Diagram">大致流程</h4>
![Object Relationship Diagram for URLRequest lifetime](https://wanghui0720.github.io/url_request_modify.svg)


 * [1.URLRequest创建， 通过url_request_context来创建URLRquest](#urlrequest)
 * [2.检查cache  然后请求创建一个stream](#request_stream)
 	* [2.1 创建URLRequestJob](#create_url_request_job)
 	* [2.2 创建Transaction](#create_transaction)
 	* [2.3 请求创建 stream](#request_one_stream)
 * [创建stream](#create_stream)
 * 发送request请求
 * [wireshark 抓http2](#wireshark)

<h4 id="urlrequest">一 . URLRequest 创建</h4>

    UrlRequestContext::CreateRequest

 <h4 id="request_stream">二. 请求创建stream</h4>
 <h4 id="create_url_request_job">创建URLRequestJob</h4>
 URLRequest 通过单例URLRequestJobManager 调用URLRequestJobFactory根据protol来创建URLRequestJob.
 比如 URLRequestFileJob  URLRequestHttpJob...
   每个url_request_context内部会维护一个URLRequestJobFactory并在build的时候初始化设置一些protocol_handler， 这些protocol_handler就是用来创建对应的URLRquestJob
   我们可以看android_webview的url_request_context的build过程.

	for (auto& scheme_handler : protocol_handlers_) {
	  job_factory->SetProtocolHandler(scheme_handler.first,
		                            std::move(scheme_handler.second));
	}
	if (data_enabled_)
	  job_factory->SetProtocolHandler(url::kDataScheme,
		                            std::make_unique<DataProtocolHandler>());

	#if !BUILDFLAG(DISABLE_FILE_SUPPORT)
	if (file_enabled_) {
	  job_factory->SetProtocolHandler(
		url::kFileScheme,
		std::make_unique<FileProtocolHandler>(base::CreateTaskRunnerWithTraits(
		    {base::MayBlock(), base::TaskPriority::USER_BLOCKING,
		     base::TaskShutdownBehavior::SKIP_ON_SHUTDOWN})));
	}
	#endif  // !BUILDFLAG(DISABLE_FILE_SUPPORT)
	#if !BUILDFLAG(DISABLE_FTP_SUPPORT)
	if (ftp_enabled_) {
	  job_factory->SetProtocolHandler(
		url::kFtpScheme, FtpProtocolHandler::Create(context->host_resolver()));
	}
	#endif  // !BUILDFLAG(DISABLE_FTP_SUPPORT)
[所以我们在使用过程中还可以通过以下api来添加我们自己的protol，就是在URLRequestContext创建的时候](#URLRequestContext)


		URLRequestContextBuilder::SetProtocolHandler

比如chrome的使用：

	#if BUILDFLAG(ENABLE_EXTENSIONS)
	  DCHECK(extension_info_map_.get());
	  // Check only for incognito (and not Chrome OS guest mode GUEST_PROFILE).
	  bool is_incognito = profile_type() == Profile::INCOGNITO_PROFILE;
	  builder->SetProtocolHandler(extensions::kExtensionScheme,
		                      extensions::CreateExtensionProtocolHandler(
		                          is_incognito, extension_info_map_.get()));
	#endif

extension_protocols.h 看一下CreateExtensionProtocolHandler的实现

	// Copyright 2014 The Chromium Authors. All rights reserved.
	// Use of this source code is governed by a BSD-style license that can be
	// found in the LICENSE file.

	#ifndef EXTENSIONS_BROWSER_EXTENSION_PROTOCOLS_H_
	#define EXTENSIONS_BROWSER_EXTENSION_PROTOCOLS_H_

	#include <memory>
	#include <string>

	#include "base/callback.h"
	#include "net/url_request/url_request_job_factory.h"

	namespace base {
	class FilePath;
	class Time;
	}

	namespace net {
	class URLRequest;
	class URLRequestJob;
	class HttpResponseHeaders;
	}

	namespace extensions {
	class InfoMap;

	using ExtensionProtocolTestHandler =
	    base::Callback<net::URLRequestJob*(net::URLRequest*,
		                               net::NetworkDelegate*,
		                               const base::FilePath&)>;

	// Builds HTTP headers for an extension request. Hashes the time to avoid
	// exposing the exact user installation time of the extension.
	net::HttpResponseHeaders* BuildHttpHeaders(
	    const std::string& content_security_policy,
	    bool send_cors_header,
	    const base::Time& last_modified_time);

	// Creates the handlers for the chrome-extension:// scheme. Pass true for
	// |is_incognito| only for incognito profiles and not for Chrome OS guest mode
	// profiles.
	std::unique_ptr<net::URLRequestJobFactory::ProtocolHandler>
	CreateExtensionProtocolHandler(bool is_incognito, InfoMap* extension_info_map);

	// Allows tests to set a special handler for chrome-extension:// urls. Note
	// that this goes through all the normal security checks; it's essentially a
	// way to map extra resources to be included in extensions.
	void SetExtensionProtocolTestHandler(ExtensionProtocolTestHandler* handler);

	}  // namespace extensions

	#endif  // EXTENSIONS_BROWSER_EXTENSION_PROTOCOLS_H_

extension_protocols.cc

	std::unique_ptr<net::URLRequestJobFactory::ProtocolHandler>
	CreateExtensionProtocolHandler(bool is_incognito,
		                       extensions::InfoMap* extension_info_map) {
          //创建ExtensionProtocolHandler
	  return std::make_unique<ExtensionProtocolHandler>(is_incognito,
		                                            extension_info_map);
	}


	class ExtensionProtocolHandler
	    : public net::URLRequestJobFactory::ProtocolHandler {
	 public:
	  ExtensionProtocolHandler(bool is_incognito,
		                   extensions::InfoMap* extension_info_map)
	      : is_incognito_(is_incognito), extension_info_map_(extension_info_map) {}

	  ~ExtensionProtocolHandler() override {}

	  net::URLRequestJob* MaybeCreateJob(
	      net::URLRequest* request,
	      net::NetworkDelegate* network_delegate) const override;

	 private:
	  const bool is_incognito_;
	  extensions::InfoMap* const extension_info_map_;
	  DISALLOW_COPY_AND_ASSIGN(ExtensionProtocolHandler);
	};

需要注意的是 自己的Handler需要继承 net::URLRequestJobFactory::ProtocolHandler并重写MaybeCreateJob因为 会通过调用handler的MaybeCreateJob来创建对应的job

	URLRequestJob* URLRequestJobFactoryImpl::MaybeCreateJobWithProtocolHandler(
	    const std::string& scheme,
	    URLRequest* request,
	    NetworkDelegate* network_delegate) const {
	  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
	  if (g_interceptor_for_testing) {
	    URLRequestJob* job = g_interceptor_for_testing->MaybeInterceptRequest(
		request, network_delegate);
	    if (job)
	      return job;
	  }

	  ProtocolHandlerMap::const_iterator it = protocol_handler_map_.find(scheme);
	  if (it == protocol_handler_map_.end())
	    return NULL;
	  return it->second->MaybeCreateJob(request, network_delegate);
	}

另外有默认内置的几个协议

	static const SchemeToFactory kBuiltinFactories[] = {
	    {"http", URLRequestHttpJob::Factory},
	    {"https", URLRequestHttpJob::Factory},

	#if BUILDFLAG(ENABLE_WEBSOCKETS)
	    {"ws", URLRequestHttpJob::Factory},
	    {"wss", URLRequestHttpJob::Factory},
	#endif  // BUILDFLAG(ENABLE_WEBSOCKETS)
	};
http请求会通过默认的内置的factory 来创建URLRquestHttpJob

<h4 id="create_transaction">创建transaction</h4>

 [URLReueqstHttpJob创建后 需要通过HttpTransactionFactory来创建一个Transaction.](#Diagram)

    rv = request_->context()->http_transaction_factory()->CreateTransaction(
        priority_, &transaction_);

http_transaction_factory也是在url_request_context创建的，下面是android_webview的http_transaction_factory的创建过程

	....
	  if (http_cache_enabled_) {
	    std::unique_ptr<HttpCache::BackendFactory> http_cache_backend;
	    if (http_cache_params_.type != HttpCacheParams::IN_MEMORY) {
	      // TODO(mmenke): Maybe merge BackendType and HttpCacheParams::Type? The
	      // first doesn't include in memory, so may require some work.
	      BackendType backend_type = CACHE_BACKEND_DEFAULT;
	      switch (http_cache_params_.type) {
		case HttpCacheParams::DISK:
		  backend_type = CACHE_BACKEND_DEFAULT;
		  break;
		case HttpCacheParams::DISK_BLOCKFILE:
		  backend_type = CACHE_BACKEND_BLOCKFILE;
		  break;
		case HttpCacheParams::DISK_SIMPLE:
		  backend_type = CACHE_BACKEND_SIMPLE;
		  break;
		case HttpCacheParams::IN_MEMORY:
		  NOTREACHED();
		  break;
	      }
	      http_cache_backend.reset(new HttpCache::DefaultBackend(
		  DISK_CACHE, backend_type, http_cache_params_.path,
		  http_cache_params_.max_size));
	    } else {
	      http_cache_backend =
		  HttpCache::DefaultBackend::InMemory(http_cache_params_.max_size);
	    }
	    //设置HttpCache为默认的http_transaction_factory
	    http_transaction_factory.reset(
		new HttpCache(std::move(http_transaction_factory),
		              std::move(http_cache_backend), true));
	  }
	  storage->set_http_transaction_factory(std::move(http_transaction_factory));

我们看到默认是HttpCache
所以最初创建的会是HttpCache::Transaction HttpCache::Transaction 启动时会进入一个状态机，
[当当前cache里没有此记录 或者cache比较忙的话 会通过HttpNetworkLayer创建一个 HttpNetworkTransaction](#Diagram)

这个HttpNetworkTransaction接下来才是真正需要从网络侧下载数据。

HttpNetworkTransaction的状态机

	  enum State {
	    STATE_THROTTLE,
	    STATE_THROTTLE_COMPLETE,
	    STATE_NOTIFY_BEFORE_CREATE_STREAM,
	    STATE_CREATE_STREAM,
	    STATE_CREATE_STREAM_COMPLETE,
	    STATE_INIT_STREAM,
	    STATE_INIT_STREAM_COMPLETE,
	    STATE_GENERATE_PROXY_AUTH_TOKEN,
	    STATE_GENERATE_PROXY_AUTH_TOKEN_COMPLETE,
	    STATE_GENERATE_SERVER_AUTH_TOKEN,
	    STATE_GENERATE_SERVER_AUTH_TOKEN_COMPLETE,
	    STATE_GET_PROVIDED_TOKEN_BINDING_KEY,
	    STATE_GET_PROVIDED_TOKEN_BINDING_KEY_COMPLETE,
	    STATE_GET_REFERRED_TOKEN_BINDING_KEY,
	    STATE_GET_REFERRED_TOKEN_BINDING_KEY_COMPLETE,
	    STATE_INIT_REQUEST_BODY,
	    STATE_INIT_REQUEST_BODY_COMPLETE,
	    STATE_BUILD_REQUEST,
	    STATE_BUILD_REQUEST_COMPLETE,
	    STATE_SEND_REQUEST,
	    STATE_SEND_REQUEST_COMPLETE,
	    STATE_READ_HEADERS,
	    STATE_READ_HEADERS_COMPLETE,
	    STATE_READ_BODY,
	    STATE_READ_BODY_COMPLETE,
	    STATE_DRAIN_BODY_FOR_AUTH_RESTART,
	    STATE_DRAIN_BODY_FOR_AUTH_RESTART_COMPLETE,
	    STATE_NONE
	  };



HttpNetworkTransaction的start方法会触发状态机的执行。


	int HttpNetworkTransaction::Start(const HttpRequestInfo* request_info,
		                          const CompletionCallback& callback,
		                          const NetLogWithSource& net_log) {
	  net_log_ = net_log;
	  request_ = request_info;
	  url_ = request_->url;

	  // Now that we have an HttpRequestInfo object, update server_ssl_config_.
	  session_->GetSSLConfig(*request_, &server_ssl_config_, &proxy_ssl_config_);

	  if (request_->load_flags & LOAD_DISABLE_CERT_REVOCATION_CHECKING) {
	    server_ssl_config_.rev_checking_enabled = false;
	    proxy_ssl_config_.rev_checking_enabled = false;
	  }

	  if (request_->load_flags & LOAD_PREFETCH)
	    response_.unused_since_prefetch = true;

	  next_state_ = STATE_THROTTLE;
	  int rv = DoLoop(OK);
	  if (rv == ERR_IO_PENDING)
	    callback_ = callback;
	  return rv;
	}

这里我们只考虑最简单的http请求
最简单的请求过程基本就是按照状态机从上到下执行。

<h4 id="create_stream">三. 创建stream</h4> [当状态为STATE_CREATE_STREAM HttpNetworkTransaction 会通过HttpStreamFactoryImpl请求创建一个HttpStreamRequest](#Diagram)


	std::unique_ptr<HttpStreamRequest> HttpStreamFactoryImpl::RequestStreamInternal(
	    const HttpRequestInfo& request_info,
	    RequestPriority priority,
	    const SSLConfig& server_ssl_config,
	    const SSLConfig& proxy_ssl_config,
	    HttpStreamRequest::Delegate* delegate,
	    WebSocketHandshakeStreamBase::CreateHelper*
		websocket_handshake_stream_create_helper,
	    HttpStreamRequest::StreamType stream_type,
	    bool enable_ip_based_pooling,
	    bool enable_alternative_services,
	    const NetLogWithSource& net_log) {
	  AddJobControllerCountToHistograms();

	  auto job_controller = std::make_unique<JobController>(
	      this, delegate, session_, job_factory_.get(), request_info,
	      /* is_preconnect = */ false, enable_ip_based_pooling,
	      enable_alternative_services, server_ssl_config, proxy_ssl_config);
	  JobController* job_controller_raw_ptr = job_controller.get();
	  job_controller_set_.insert(std::move(job_controller));
	  return job_controller_raw_ptr->Start(delegate,
		                               websocket_handshake_stream_create_helper,
		                               net_log, stream_type, priority);
	}

HttpStreamFactoryImpl::JobController 的start会创建一个request 并启动一个状态机

	int HttpStreamFactoryImpl::JobController::DoLoop(int rv) {
	  DCHECK_NE(next_state_, STATE_NONE);
	  do {
	    State state = next_state_;
	    next_state_ = STATE_NONE;
	    switch (state) {
	      case STATE_RESOLVE_PROXY:
		DCHECK_EQ(OK, rv);
		rv = DoResolveProxy();
		break;
	      case STATE_RESOLVE_PROXY_COMPLETE:
		rv = DoResolveProxyComplete(rv);
		break;
	      case STATE_CREATE_JOBS:
		DCHECK_EQ(OK, rv);
		rv = DoCreateJobs();
		break;
	      default:
		NOTREACHED() << "bad state";
		break;
	    }
	  } while (next_state_ != STATE_NONE && rv != ERR_IO_PENDING);
	  return rv;
	}

HttpStreamFactoryImpl通过 HttpStreamFactoryImpl::JobController会创建一个HttpStreamFactoryImpl::Job并调用job的start方法

      main_job_ = job_factory_->CreateMainJob(
          this, PRECONNECT, session_, request_info_, IDLE, proxy_info_,
          server_ssl_config_, proxy_ssl_config_, destination, origin_url,
          enable_ip_based_pooling_, session_->net_log());


再看一下HttpStreamFactory::Job的构造函数


	HttpStreamFactoryImpl::Job::Job(Delegate* delegate,
		                        JobType job_type,
		                        HttpNetworkSession* session,
		                        const HttpRequestInfo& request_info,
		                        RequestPriority priority,
		                        const ProxyInfo& proxy_info,
		                        const SSLConfig& server_ssl_config,
		                        const SSLConfig& proxy_ssl_config,
		                        HostPortPair destination,
		                        GURL origin_url,
		                        NextProto alternative_protocol,
		                        QuicTransportVersion quic_version,
		                        const ProxyServer& alternative_proxy_server,
		                        bool enable_ip_based_pooling,
		                        NetLog* net_log)
	    : request_info_(request_info),
	      priority_(priority),
	      proxy_info_(proxy_info),
	      server_ssl_config_(server_ssl_config),
	      proxy_ssl_config_(proxy_ssl_config),
	      net_log_(
		  NetLogWithSource::Make(net_log, NetLogSourceType::HTTP_STREAM_JOB)),
	      io_callback_(base::Bind(&Job::OnIOComplete, base::Unretained(this))),
	      connection_(new ClientSocketHandle),
	      session_(session),
	      state_(STATE_NONE),
	      next_state_(STATE_NONE),
	      destination_(destination),
	      origin_url_(origin_url),
	...
	}

我们可以看到这个job的成员变量 connection_ 新创建了一个ClientSocketHandle
main_job->start() 又会启动一个状态机
<h4 id="connect">Stream创建</h4>

	int HttpStreamFactoryImpl::Job::DoLoop(int result) {
	  DCHECK_NE(next_state_, STATE_NONE);
	  int rv = result;
	  do {
	    State state = next_state_;
	    // Added to investigate crbug.com/711721.
	    state_ = state;
	    next_state_ = STATE_NONE;
	    switch (state) {
	      case STATE_START:
		DCHECK_EQ(OK, rv);
		rv = DoStart();
		break;
	      case STATE_WAIT:
		DCHECK_EQ(OK, rv);
		rv = DoWait();
		break;
	      case STATE_WAIT_COMPLETE:
		rv = DoWaitComplete(rv);
		break;
	      case STATE_EVALUATE_THROTTLE:
		DCHECK_EQ(OK, rv);
		rv = DoEvaluateThrottle();
		break;
	      case STATE_INIT_CONNECTION:
		DCHECK_EQ(OK, rv);
		rv = DoInitConnection();
		break;
	      case STATE_INIT_CONNECTION_COMPLETE:
		rv = DoInitConnectionComplete(rv);
		break;
	      case STATE_WAITING_USER_ACTION:
		rv = DoWaitingUserAction(rv);
		break;
	      case STATE_RESTART_TUNNEL_AUTH:
		DCHECK_EQ(OK, rv);
		rv = DoRestartTunnelAuth();
		break;
	      case STATE_RESTART_TUNNEL_AUTH_COMPLETE:
		rv = DoRestartTunnelAuthComplete(rv);
		break;
	      case STATE_CREATE_STREAM:
		DCHECK_EQ(OK, rv);
		rv = DoCreateStream();
		break;
	      case STATE_CREATE_STREAM_COMPLETE:
		rv = DoCreateStreamComplete(rv);
		break;
	      default:
		NOTREACHED() << "bad state";
		rv = ERR_FAILED;
		break;
	    }
	  } while (rv != ERR_IO_PENDING && next_state_ != STATE_NONE);
	  return rv;
	}
在状态为STATE_INIT_CONNECTION的时候
五 调用会通过client_socket_pool_manager 初始化clientsockethandle，并通过成员变量pool_来请求创建socket


	int ClientSocketHandle::Init(
	    const std::string& group_name,
	    const scoped_refptr<typename PoolType::SocketParams>& socket_params,
	    RequestPriority priority,
	    ClientSocketPool::RespectLimits respect_limits,
	    const CompletionCallback& callback,
	    PoolType* pool,
	    const NetLogWithSource& net_log) {
	  requesting_source_ = net_log.source();

	  CHECK(!group_name.empty());
	  ResetInternal(true);
	  ResetErrorState();
	  pool_ = pool;
	  group_name_ = group_name;
	  int rv = pool_->RequestSocket(group_name, &socket_params, priority,
		                        respect_limits, this, callback_, net_log);
	  if (rv == ERR_IO_PENDING) {
	    user_callback_ = callback;
	  } else {
	    HandleInitCompletion(rv);
	  }
	  return rv;
	}


我们看看如果是普通http 这个pool_会是什么, client_socket_pool_manager会调用InitSocketPoolHelper来初始化 clientsockethandle

	// The meat of the implementation for the InitSocketHandleForHttpRequest,
	// InitSocketHandleForRawConnect and PreconnectSocketsForHttpRequest methods.
	int InitSocketPoolHelper(ClientSocketPoolManager::SocketGroupType group_type,
	...
		                 HttpRequestInfo::RequestMotivation motivation) {
	  scoped_refptr<HttpProxySocketParams> http_proxy_params;
	  scoped_refptr<SOCKSSocketParams> socks_params;
	  std::unique_ptr<HostPortPair> proxy_host_port;

         //clientsockethandle的一些配置
	  bool using_ssl = group_type == ClientSocketPoolManager::SSL_GROUP;
	  HostPortPair origin_host_port = endpoint;

	  if (!using_ssl && session->params().testing_fixed_http_port != 0) {
	    origin_host_port.set_port(session->params().testing_fixed_http_port);
	  } else if (using_ssl && session->params().testing_fixed_https_port != 0) {
	    origin_host_port.set_port(session->params().testing_fixed_https_port);
	  }

	  bool disable_resolver_cache =
	      request_load_flags & LOAD_BYPASS_CACHE ||
	      request_load_flags & LOAD_VALIDATE_CACHE ||
	      request_load_flags & LOAD_DISABLE_CACHE;

	  int load_flags = request_load_flags;
	  if (session->params().ignore_certificate_errors)
	    load_flags |= LOAD_IGNORE_ALL_CERT_ERRORS;

	  // Build the string used to uniquely identify connections of this type.
	  // Determine the host and port to connect to.
	  std::string connection_group = origin_host_port.ToString();
	  DCHECK(!connection_group.empty());
	  if (group_type == ClientSocketPoolManager::FTP_GROUP) {
	    // Combining FTP with forced SPDY over SSL would be a "path to madness".
	    // Make sure we never do that.
	    DCHECK(!using_ssl);
	    connection_group = "ftp/" + connection_group;
	  }
	  if (using_ssl) {
	    connection_group = "ssl/" + connection_group;
	  }

	  ClientSocketPool::RespectLimits respect_limits =
	      ClientSocketPool::RespectLimits::ENABLED;
	  if ((request_load_flags & LOAD_IGNORE_LIMITS) != 0)
	    respect_limits = ClientSocketPool::RespectLimits::DISABLED;

	  // CombineConnectAndWritePolicy for SSL and non-SSL connections.
	  TransportSocketParams::CombineConnectAndWritePolicy
	      non_ssl_combine_connect_and_write_policy =
		  TransportSocketParams::COMBINE_CONNECT_AND_WRITE_DEFAULT;
	  TransportSocketParams::CombineConnectAndWritePolicy
	      ssl_combine_connect_and_write_policy =
		  TransportSocketParams::COMBINE_CONNECT_AND_WRITE_DEFAULT;

	  if (session->params().tcp_fast_open_mode ==
	      HttpNetworkSession::Params::TcpFastOpenMode::ENABLED_FOR_SSL_ONLY) {
	    ssl_combine_connect_and_write_policy =
		TransportSocketParams::COMBINE_CONNECT_AND_WRITE_DESIRED;
	  } else if (session->params().tcp_fast_open_mode ==
		     HttpNetworkSession::Params::TcpFastOpenMode::ENABLED_FOR_ALL) {
	    non_ssl_combine_connect_and_write_policy =
		TransportSocketParams::COMBINE_CONNECT_AND_WRITE_DESIRED;
	    ssl_combine_connect_and_write_policy =
		TransportSocketParams::COMBINE_CONNECT_AND_WRITE_DESIRED;
	  }

	  if (!proxy_info.is_direct()) {
	...
	  }

	  // Change group name if privacy mode is enabled.
	  if (privacy_mode == PRIVACY_MODE_ENABLED)
	    connection_group = "pm/" + connection_group;

	  // Deal with SSL - which layers on top of any given proxy.
	  if (using_ssl) {
	...
	  }

	  // Finally, get the connection started.

	  if (proxy_info.is_http() || proxy_info.is_https()) {
	...
	  }

	  if (proxy_info.is_socks()) {
	...
	  }

	  DCHECK(proxy_info.is_direct());
	  scoped_refptr<TransportSocketParams> tcp_params = new TransportSocketParams(
	      origin_host_port, disable_resolver_cache, resolution_callback,
	      non_ssl_combine_connect_and_write_policy);
	  //真正的clientsocketpool
	  TransportClientSocketPool* pool =
	      session->GetTransportSocketPool(socket_pool_type);
	  if (num_preconnect_streams) {
	    RequestSocketsForPool(pool, connection_group, tcp_params,
		                  num_preconnect_streams, net_log, motivation);
	    return OK;
	  }

	  return socket_handle->Init(connection_group, tcp_params, request_priority,
		                     respect_limits, callback, pool, net_log);
	}

看个堆栈

	(gdb) bt
	#0  RequestSocketInternal () at ../../net/socket/client_socket_pool_base.cc:396
	#1  0x00007fffef8c744b in RequestSocket () at ../../net/socket/client_socket_pool_base.cc:315
	warning: Could not find DWO CU obj/net/net/transport_client_socket_pool.dwo(0xb747383281585d60) referenced by CU at offset 0x6f628d [in module /home/wanghui/SourceCode/SourceCode/chromium/src/out/Default/./libnet.so]
	#2  0x00007fffef92234c in RequestSocket () at ../../net/socket/client_socket_pool_base.h:796
	#3  0x00007fffef920ec6 in net::TransportClientSocketPool::RequestSocket(std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> > const&, void const*, net::RequestPriority, net::ClientSocketPool::RespectLimits, net::ClientSocketHandle*, base::RepeatingCallback<void (int)> const&, net::NetLogWithSource const&) () at ../../net/socket/transport_client_socket_pool.cc:500
	#4  0x00007fffef572b94 in Init<net::TransportClientSocketPool> () at ../../net/socket/client_socket_handle.h:254
	#5  0x00007fffef8dd51d in InitSocketPoolHelper () at ../../net/socket/client_socket_pool_manager.cc:266
	#6  0x00007fffef8db2f7 in net::InitSocketHandleForHttpRequest(net::ClientSocketPoolManager::SocketGroupType, net::HostPortPair const&, net::HttpRequestHeaders const&, int, net::RequestPriority, net::HttpNetworkSession*, net::ProxyInfo const&, bool, net::SSLConfig const&, net::SSLConfig const&, net::PrivacyMode, net::NetLogWithSource const&, net::ClientSocketHandle*, base::RepeatingCallback<int (net::AddressList const&, net::NetLogWithSource const&)> const&, base::RepeatingCallback<void (int)> const&) () at ../../net/socket/client_socket_pool_manager.cc:354
	#7  0x00007fffef5c5ef5 in DoInitConnectionImpl () at ../../net/http/http_stream_factory_impl_job.cc:988
	#8  0x00007fffef5c19e3 in net::HttpStreamFactoryImpl::Job::DoInitConnection() () at ../../net/http/http_stream_factory_impl_job.cc:840
	#9  0x00007fffef5c0ea2 in net::HttpStreamFactoryImpl::Job::DoLoop(int) () at ../../net/http/http_stream_factory_impl_job.cc:715
	#10 0x00007fffef5bcaf1 in RunLoop () at ../../net/http/http_stream_factory_impl_job.cc:568
	#11 0x00007fffef5bc493 in net::HttpStreamFactoryImpl::Job::StartInternal() () at ../../net/http/http_stream_factory_impl_job.cc:749
	#12 0x00007fffef5bc391 in net::HttpStreamFactoryImpl::Job::Start(net::HttpStreamRequest::StreamType) () at ../../net/http/http_stream_factory_impl_job.cc:265


通过以上堆栈可以看到TransportClientSocketPool 通过基类 client_socket_pool_base来请求创建socket

看一下client_socket_pool_base::RequestSocketInternal的实现

	int ClientSocketPoolBaseHelper::RequestSocketInternal(
	    const std::string& group_name,
	    const Request& request,
	    HttpRequestInfo::RequestMotivation motivation) {
	  ClientSocketHandle* const handle = request.handle();
	  const bool preconnecting = !handle;
	  Group* group = GetOrCreateGroup(group_name);

	  if (!(request.flags() & NO_IDLE_SOCKETS)) {
	    // Try to reuse a socket.  尝试reuse soket， 这个通过group这个判断 group是pair <host, port>
	    if (AssignIdleSocketToRequest(request, group))
	      return OK;
	  }

	  // If there are more ConnectJobs than pending requests, don't need to do
	  // anything.  Can just wait for the extra job to connect, and then assign it
	  // to the request.
	  if (!preconnecting && group->TryToUseUnassignedConnectJob())
	    return ERR_IO_PENDING;

	  // Can we make another active socket now?
	  if (!group->HasAvailableSocketSlot(max_sockets_per_group_) &&
	      request.respect_limits() == ClientSocketPool::RespectLimits::ENABLED) {
	    // TODO(willchan): Consider whether or not we need to close a socket in a
	    // higher layered group. I don't think this makes sense since we would just
	    // reuse that socket then if we needed one and wouldn't make it down to this
	    // layer.
	    request.net_log().AddEvent(
		NetLogEventType::SOCKET_POOL_STALLED_MAX_SOCKETS_PER_GROUP);
	    return ERR_IO_PENDING;
	  }

	  if (ReachedMaxSocketsLimit() &&
	      request.respect_limits() == ClientSocketPool::RespectLimits::ENABLED) {
	    // NOTE(mmenke):  Wonder if we really need different code for each case
	    // here.  Only reason for them now seems to be preconnects.
	    if (idle_socket_count() > 0) {
	      // There's an idle socket in this pool. Either that's because there's
	      // still one in this group, but we got here due to preconnecting bypassing
	      // idle sockets, or because there's an idle socket in another group.
	      bool closed = CloseOneIdleSocketExceptInGroup(group);
	      if (preconnecting && !closed)
		return ERR_PRECONNECT_MAX_SOCKET_LIMIT;
	    } else {
	      // We could check if we really have a stalled group here, but it requires
	      // a scan of all groups, so just flip a flag here, and do the check later.
	      request.net_log().AddEvent(
		  NetLogEventType::SOCKET_POOL_STALLED_MAX_SOCKETS);
	      return ERR_IO_PENDING;
	    }
	  }

	  // We couldn't find a socket to reuse, and there's space to allocate one,
	  // so allocate and connect a new one.
	  // 如果没有可以重用的socket直接新建一个job
	  std::unique_ptr<ConnectJob> connect_job(
	      connect_job_factory_->NewConnectJob(group_name, request, this));

	  connect_job->set_motivation(motivation);

	  int rv = connect_job->Connect();
	  if (rv == OK) {
	    LogBoundConnectJobToRequest(connect_job->net_log().source(), request);
	    if (!preconnecting) {
	      HandOutSocket(connect_job->PassSocket(), ClientSocketHandle::UNUSED,
		            connect_job->connect_timing(), handle, base::TimeDelta(),
		            group, request.net_log());
	    } else {
	      AddIdleSocket(connect_job->PassSocket(), group);
	    }
	  } else if (rv == ERR_IO_PENDING) {
	    // If we don't have any sockets in this group, set a timer for potentially
	    // creating a new one.  If the SYN is lost, this backup socket may complete
	    // before the slow socket, improving end user latency.
	    if (connect_backup_jobs_enabled_ && group->IsEmpty()) {
	      group->StartBackupJobTimer(group_name, this);
	    }

	    connecting_socket_count_++;

	    group->AddJob(std::move(connect_job), preconnecting);
	  } else {
	    LogBoundConnectJobToRequest(connect_job->net_log().source(), request);
	    std::unique_ptr<StreamSocket> error_socket;
	    if (!preconnecting) {
	      DCHECK(handle);
	      connect_job->GetAdditionalErrorState(handle);
	      error_socket = connect_job->PassSocket();
	    }
	    if (error_socket) {
	      HandOutSocket(std::move(error_socket), ClientSocketHandle::UNUSED,
		            connect_job->connect_timing(), handle, base::TimeDelta(),
		            group, request.net_log());
	    } else if (group->IsEmpty()) {
	      RemoveGroup(group_name);
	    }
	  }

	  return rv;
	}

我们假如当前第一次打开页面，然后没有可以重用的socket， 就会创建一个connect_job ，http请求会创建一个TransportConnectJob

	std::unique_ptr<ConnectJob>
	TransportClientSocketPool::TransportConnectJobFactory::NewConnectJob(
	    const std::string& group_name,
	    const PoolBase::Request& request,
	    ConnectJob::Delegate* delegate) const {
	  return std::unique_ptr<ConnectJob>(new TransportConnectJob(
	      group_name, request.priority(), request.respect_limits(),
	      request.params(), ConnectionTimeout(), client_socket_factory_,
	      socket_performance_watcher_factory_, host_resolver_, delegate, net_log_));
	}

然后调用TransportportConnectJob的connect方法

job->connect会调用

	int TransportConnectJob::ConnectInternal() {
	  next_state_ = STATE_RESOLVE_HOST;
	  return DoLoop(OK);
	}

把状态机初始化为STATE_RESOLVE_HOST

	int TransportConnectJob::DoLoop(int result) {
	  DCHECK_NE(next_state_, STATE_NONE);

	  int rv = result;
	  do {
	    State state = next_state_;
	    next_state_ = STATE_NONE;
	    switch (state) {
	      case STATE_RESOLVE_HOST:
		DCHECK_EQ(OK, rv);
		rv = DoResolveHost();
		break;
	      case STATE_RESOLVE_HOST_COMPLETE:
		rv = DoResolveHostComplete(rv);
		break;
	      case STATE_TRANSPORT_CONNECT:
		DCHECK_EQ(OK, rv);
		rv = DoTransportConnect();
		break;
	      case STATE_TRANSPORT_CONNECT_COMPLETE:
		rv = DoTransportConnectComplete(rv);
		break;
	      default:
		NOTREACHED();
		rv = ERR_FAILED;
		break;
	    }
	  } while (rv != ERR_IO_PENDING && next_state_ != STATE_NONE);

	  return rv;
	}

当状态机为STATE_TRANSPORT_CONNECT 的时候执行 DoTransportConnect

	int TransportConnectJob::DoTransportConnect() {
	  next_state_ = STATE_TRANSPORT_CONNECT_COMPLETE;
	  // Create a |SocketPerformanceWatcher|, and pass the ownership.
	  std::unique_ptr<SocketPerformanceWatcher> socket_performance_watcher;
	  if (socket_performance_watcher_factory_) {
	    socket_performance_watcher =
		socket_performance_watcher_factory_->CreateSocketPerformanceWatcher(
		    SocketPerformanceWatcherFactory::PROTOCOL_TCP, addresses_);
	  }
	  //创建socket
	  transport_socket_ = client_socket_factory_->CreateTransportClientSocket(
	      addresses_, std::move(socket_performance_watcher), net_log().net_log(),
	      net_log().source());
	...

	  int rv = transport_socket_->Connect(
	      base::Bind(&TransportConnectJob::OnIOComplete, base::Unretained(this)));
	  if (rv == ERR_IO_PENDING && try_ipv6_connect_with_ipv4_fallback) {
	    fallback_timer_.Start(
		FROM_HERE, base::TimeDelta::FromMilliseconds(kIPv6FallbackTimerInMs),
		this, &TransportConnectJob::DoIPv6FallbackTransportConnect);
	  }
	  return rv;

通过CreateTransportClientSocket来创建socket


	  std::unique_ptr<StreamSocket> CreateTransportClientSocket(
	      const AddressList& addresses,
	      std::unique_ptr<SocketPerformanceWatcher> socket_performance_watcher,
	      NetLog* net_log,
	      const NetLogSource& source) override {
	    return std::unique_ptr<StreamSocket>(new TCPClientSocket(
		addresses, std::move(socket_performance_watcher), net_log, source));
	  }

TCPClientSocket

	TCPClientSocket::TCPClientSocket(
	    const AddressList& addresses,
	    std::unique_ptr<SocketPerformanceWatcher> socket_performance_watcher,
	    net::NetLog* net_log,
	    const net::NetLogSource& source)
	    : socket_performance_watcher_(socket_performance_watcher.get()),
	      socket_(new TCPSocket(std::move(socket_performance_watcher),
		                    net_log,
		                    source)),
	      addresses_(addresses),
	      current_address_index_(-1),
	      next_connect_state_(CONNECT_STATE_NONE),
	      previously_disconnected_(false),
	      total_received_bytes_(0) {}

TCPSocket

	#if defined(OS_WIN)
	typedef TCPSocketWin TCPSocket;
	#elif defined(OS_POSIX)
	typedef TCPSocketPosix TCPSocket;
	#endif

	TCPSocketPosix::TCPSocketPosix(
	    std::unique_ptr<SocketPerformanceWatcher> socket_performance_watcher,
	    NetLog* net_log,
	    const NetLogSource& source)
	    : socket_performance_watcher_(std::move(socket_performance_watcher)),
	      use_tcp_fastopen_(false),
	      tcp_fastopen_write_attempted_(false),
	      tcp_fastopen_connected_(false),
	      tcp_fastopen_status_(TCP_FASTOPEN_STATUS_UNKNOWN),
	      logging_multiple_connect_attempts_(false),
	      net_log_(NetLogWithSource::Make(net_log, NetLogSourceType::SOCKET)) {
	  net_log_.BeginEvent(NetLogEventType::SOCKET_ALIVE,
		              source.ToEventParametersCallback());
	}

	 int TCPSocketPosix::Open(AddressFamily family) {
	  DCHECK(!socket_);
	  socket_.reset(new SocketPosix);
	  int rv = socket_->Open(ConvertAddressFamily(family));
	  if (rv != OK)
	    socket_.reset();
	  return rv;
	}


创建socket并connect成功后 会讲socket句柄给clientsockethandle

	int rv = connect_job->Connect();
	  if (rv == OK) {
	    LogBoundConnectJobToRequest(connect_job->net_log().source(), request);
	    if (!preconnecting) {
	      HandOutSocket(connect_job->PassSocket(), ClientSocketHandle::UNUSED,
		            connect_job->connect_timing(), handle, base::TimeDelta(),
		            group, request.net_log());
	    } else {
	      AddIdleSocket(connect_job->PassSocket(), group);
	    }
	  } else if (rv == ERR_IO_PENDING) {

调用HandOutSocket

	  void ClientSocketPoolBaseHelper::HandOutSocket(
	    std::unique_ptr<StreamSocket> socket,
	    ClientSocketHandle::SocketReuseType reuse_type,
	    const LoadTimingInfo::ConnectTiming& connect_timing,
	    ClientSocketHandle* handle,
	    base::TimeDelta idle_time,
	    Group* group,
	    const NetLogWithSource& net_log) {
	  DCHECK(socket);
	  handle->SetSocket(std::move(socket));
	  handle->set_reuse_type(reuse_type);
	  handle->set_idle_time(idle_time);
	  handle->set_pool_id(pool_generation_number_);
	  handle->set_connect_timing(connect_timing);

[再回到stream的创建，现在我们已经有一个已经connect的socket](#connect)

int HttpStreamFactoryImpl::Job::DoCreateStream() {
  DCHECK(connection_->socket() || existing_spdy_session_.get() || using_quic_);
  DCHECK(!using_quic_);

  next_state_ = STATE_CREATE_STREAM_COMPLETE;

  if (using_ssl_ && connection_->socket()) {
    SSLClientSocket* ssl_socket =
        static_cast<SSLClientSocket*>(connection_->socket());
    RecordChannelIDKeyMatch(ssl_socket, session_->context().channel_id_service,
                            destination_.HostForURL());
  }

  if (!using_spdy_) {
    DCHECK(!expect_spdy_);
    // We may get ftp scheme when fetching ftp resources through proxy.
    bool using_proxy = (proxy_info_.is_http() || proxy_info_.is_https()) &&
                       (request_info_.url.SchemeIs(url::kHttpScheme) ||
                        request_info_.url.SchemeIs(url::kFtpScheme));
    if (delegate_->for_websockets()) {
      DCHECK_NE(job_type_, PRECONNECT);
      DCHECK(delegate_->websocket_handshake_stream_create_helper());
      websocket_stream_ =
          delegate_->websocket_handshake_stream_create_helper()
              ->CreateBasicStream(std::move(connection_), using_proxy);
    } else {
    /创建BasicStream
      stream_ = std::make_unique<HttpBasicStream>(
          std::move(connection_), using_proxy,
          session_->params().http_09_on_non_default_ports_enabled);
    }
    return OK;
  }

可以看到把connect_传给了HttpBasicStream.
这个connect_就是我们之前clientsockethandle并且有一个已经connect的socket

然后调用回调

	void HttpNetworkTransaction::OnStreamReady(const SSLConfig& used_ssl_config,
		                                   const ProxyInfo& used_proxy_info,
		                                   std::unique_ptr<HttpStream> stream) {
	  DCHECK_EQ(STATE_CREATE_STREAM_COMPLETE, next_state_);
	  DCHECK(stream_request_.get());

	  if (stream_) {
	    total_received_bytes_ += stream_->GetTotalReceivedBytes();
	    total_sent_bytes_ += stream_->GetTotalSentBytes();
	  }
	  //设置stream。
	  stream_ = std::move(stream);
	  stream_->SetRequestHeadersCallback(request_headers_callback_);
	  server_ssl_config_ = used_ssl_config;
	  proxy_info_ = used_proxy_info;
	  response_.was_alpn_negotiated = stream_request_->was_alpn_negotiated();
	  response_.alpn_negotiated_protocol =
	      NextProtoToString(stream_request_->negotiated_protocol());
	  response_.was_fetched_via_spdy = stream_request_->using_spdy();
	  response_.was_fetched_via_proxy = !proxy_info_.is_direct();
	  if (response_.was_fetched_via_proxy && !proxy_info_.is_empty())
	    response_.proxy_server = proxy_info_.proxy_server();
	  else if (!response_.was_fetched_via_proxy && proxy_info_.is_direct())
	    response_.proxy_server = ProxyServer::Direct();
	  else
	    response_.proxy_server = ProxyServer();
	  OnIOComplete(OK);
	}

将stream设置给httpnetworktransaction


<h4 id="wireshark">wireshark抓取http2</h4>

这种方式只适合chromium

1. 创建一个file 比如 touch ~/ssllog
2. 设置comandline  --ssl-key-log-file=上面创建文件的绝对路径
3. 启动wireshark  Edit -> Preference -> Protocols -> SSL -> (Pre)-Master-Secret log filename 填写上面文件的绝对路径

