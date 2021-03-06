﻿using System;
using System.Threading.Tasks;
using Microsoft.Owin;
using SAML2.Logging;
using SAML2.Bindings;
using SAML2;
using SAML2.Utils;
using SAML2.Protocol;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Runtime.ExceptionServices;
using Microsoft.Owin.Security.Notifications;
using Microsoft.Owin.Security;
using System.Linq;

namespace Owin.Security.Saml
{
    internal class SamlLoginHandler : SamlAbstractEndpointHandler
    {
        /// <summary>
        /// Logger instance.
        /// </summary>
        private static readonly IInternalLogger Logger = LoggerProvider.LoggerFor(typeof(SamlLoginHandler));

        private readonly Func<string, object> getFromCache;
        private readonly IDictionary<string, object> session;
        private readonly Action<string, object, DateTime> setInCache;

        /// <summary>
        /// Key used to save temporary session id
        /// </summary>
        public const string IdpTempSessionKey = "TempIDPId";

        /// <summary>
        /// Key used to override <c>ForceAuthn</c> setting
        /// </summary>
        public const string IdpForceAuthn = "IDPForceAuthn";

        /// <summary>
        /// Key used to override IsPassive setting
        /// </summary>
        public const string IdpIsPassive = "IDPIsPassive";
        private readonly SamlAuthenticationOptions options;

        /// <summary>
        /// Constructor for LoginHandler
        /// </summary>
        /// <param name="options">The authentication options.</param>
        public SamlLoginHandler(SamlAuthenticationOptions options)
            : base(options.Configuration)
        {
            if (options == null) throw new ArgumentNullException(nameof(options));
            this.options = options;
            getFromCache = options.GetFromCache;
            setInCache = options.SetInCache;
            session = options.Session;
        }

        /// <summary>
        /// Invokes the login procedure (2nd leg of SP-Initiated login). Analagous to Saml20SignonHandler from ASP.Net DLL
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        public async Task<AuthenticationTicket> Invoke(IOwinContext context)
        {
            Logger.Debug(TraceMessages.SignOnHandlerCalled);
            ExceptionDispatchInfo authFailedEx = null;
            try {
                var messageReceivedNotification = new MessageReceivedNotification<SamlMessage, SamlAuthenticationOptions>(context, options)
                {
                    ProtocolMessage = new SamlMessage(context, configuration, null)
                };
                await options.Notifications.MessageReceived(messageReceivedNotification);
                if (messageReceivedNotification.HandledResponse) {
                    return null; // GetHandledResponseTicket()
                }
                if (messageReceivedNotification.Skipped) {
                    return null;
                }
                var requestParams = await HandleResponse(context);
                var assertion = context.Get<Saml20Assertion>("Saml2:assertion");
                var securityTokenReceivedNotification = new SecurityTokenReceivedNotification<SamlMessage, SamlAuthenticationOptions>(context, options)
                {
                    ProtocolMessage = new SamlMessage(context, configuration, assertion)
                };
                await options.Notifications.SecurityTokenReceived(securityTokenReceivedNotification);
                if (securityTokenReceivedNotification.HandledResponse) {
                    return null; // GetHandledResponseTicket();
                }
                if (securityTokenReceivedNotification.Skipped) {
                    return null;
                }

                var ticket = await GetAuthenticationTicket(context, requestParams);

                var securityTokenValidatedNotification = new SecurityTokenValidatedNotification<SamlMessage, SamlAuthenticationOptions>(context, options)
                {
                    AuthenticationTicket = ticket,
                    ProtocolMessage = new SamlMessage(context, configuration, assertion)
                };

                await options.Notifications.SecurityTokenValidated(securityTokenValidatedNotification);
                if (securityTokenValidatedNotification.HandledResponse) {
                    return null; // GetHandledResponseTicket();
                }
                if (securityTokenValidatedNotification.Skipped) {
                    return null; // null;
                }
                // Flow possible changes
                ticket = securityTokenValidatedNotification.AuthenticationTicket;
                context.Authentication.AuthenticationResponseGrant = new AuthenticationResponseGrant(ticket.Identity, ticket.Properties);
                return ticket;
            }
            catch (Exception ex) {
                var endpointException = new SamlEndpointException("Error during login request, see inner exception", ex);
                authFailedEx = ExceptionDispatchInfo.Capture(endpointException);
            }
            if (authFailedEx != null) {
                Logger.Error("Exception occurred while processing message: " + authFailedEx.SourceException);
                var message = new SamlMessage(context, configuration, context.Get<Saml20Assertion>("Saml2:assertion"));
                var authenticationFailedNotification = new AuthenticationFailedNotification<SamlMessage, SamlAuthenticationOptions>(context, options)
                {
                    ProtocolMessage = message,
                    Exception = authFailedEx.SourceException
                };
                await options.Notifications.AuthenticationFailed(authenticationFailedNotification);
                if (authenticationFailedNotification.HandledResponse) {
                    return null;//GetHandledResponseTicket();
                }
                if (authenticationFailedNotification.Skipped) {
                    return null; //null
                }
                authFailedEx.Throw();
            }
            return null;
        }

        private Task<AuthenticationTicket> GetAuthenticationTicket(IOwinContext context, NameValueCollection requestParams)
        {
            var assertion = context.Get<Saml20Assertion>("Saml2:assertion");
            if (assertion == null)
                throw new InvalidOperationException("no assertion found with which to create a ticket");

            var authenticationProperties = new AuthenticationProperties
            {
                ExpiresUtc = DetermineExpiration(assertion),
                // IssuedUtc = DateTimeOffset.UtcNow,
                IsPersistent = true,
                AllowRefresh = true,
                RedirectUri = options.RedirectAfterLogin
            };

            var relayState = requestParams["RelayState"];
            if (!string.IsNullOrEmpty(relayState))
            {
                try
                {
                    var challengeProperties = new AuthenticationProperties(Compression.DeflateDecompress(relayState).FromDelimitedString().ToDictionary(k => k.Key, v => v.Value));
                    if (challengeProperties.RedirectUri != null) authenticationProperties.RedirectUri = challengeProperties.RedirectUri;
                    foreach (var kvp in challengeProperties.Dictionary.Except(authenticationProperties.Dictionary))
                        authenticationProperties.Dictionary.Add(kvp);
                }
                catch (Exception e)
                {
                    Logger.Error($"Received invalid RelayState from DigiD while authenticating. RelayState={relayState}", e);
                }
            }
            return Task.FromResult(new AuthenticationTicket(assertion.ToClaimsIdentity(options.SignInAsAuthenticationType), authenticationProperties));
        }

        /// <summary>
        ///     Determines the expiration date of the given <see cref="Saml20Assertion" />. The result of this method will obey
        ///     <see cref="SamlAuthenticationOptions.MaxSessionExpiration" />.
        /// </summary>
        /// <param name="assertion">The assertion to determine the expiration time of.</param>
        /// <returns>The experiation time, if any.</returns>
        private DateTime? DetermineExpiration(Saml20Assertion assertion)
        {
            var fromAuthStatements = assertion.Assertion.GetAuthnStatements().Select(authn => authn.SessionNotOnOrAfter).Min();
            if (options.MaxSessionExpiration.HasValue)
            {
                var maxSessionTime = options.MaxSessionExpiration.Value;
                var now = DateTime.UtcNow;
                var maxDateTime = DateTime.MaxValue;
                if (maxDateTime - now < maxSessionTime)
                {
                    // If now + maxDateTime is unrepresentable, let's just return the maximum value.
                    return maxDateTime;
                }

                // The maximum.
                var max = now + maxSessionTime;
                if (max < fromAuthStatements || !fromAuthStatements.HasValue)
                {
                    return max;
                }
            }

            return fromAuthStatements;
        }

        private Task<NameValueCollection> HandleResponse(IOwinContext context)
        {
            Action<Saml20Assertion> loginAction = a => DoSignOn(context, a);

            // Some IdP's are known to fail to set an actual value in the SOAPAction header
            // so we just check for the existence of the header field.
            if (context.Request.Headers.ContainsKey(SoapConstants.SoapAction)) {
                Utility.HandleSoap(
                    GetBuilder(context),
                    context.Request.Body,
                    configuration,
                    loginAction,
                    getFromCache,
                    setInCache,
                    session);
                return Task.FromResult(context.Request.GetRequestParameters().ToNameValueCollection());
            }

            var requestParams = context.Request.GetRequestParameters().ToNameValueCollection();
            if (!string.IsNullOrWhiteSpace(requestParams["SAMLart"])) {
                HandleArtifact(context);
            } else {
                var samlResponse = requestParams["SamlResponse"];
                if (!string.IsNullOrWhiteSpace(samlResponse)) {
                    var assertion = Utility.HandleResponse(configuration, samlResponse, session, getFromCache, setInCache);
                    loginAction(assertion);
                } else {
                    if ((configuration.CommonDomainCookie?.Enabled ?? false) && context.Request.Query["r"] == null
                            && requestParams["cidp"] == null) {
                        Logger.Debug(TraceMessages.CommonDomainCookieRedirectForDiscovery);
                        context.Response.Redirect(configuration.CommonDomainCookie.LocalReaderEndpoint);
                    } else {
                        Logger.WarnFormat(ErrorMessages.UnauthenticatedAccess, context.Request.Uri.OriginalString);
                        throw new InvalidOperationException("Response request recieved without any response data");
                    }
                }
            }

            return Task.FromResult(requestParams);
        }

        private void HandleArtifact(IOwinContext context)
        {
            var builder = GetBuilder(context);
            // TODO: Need params version of these!
            var inputStream = builder.ResolveArtifact(context.Request.Query["SAMLart"], context.Request.Query["relayState"], configuration);

            Utility.HandleSoap(builder, inputStream, configuration, a => DoSignOn(context, a), getFromCache, setInCache, session);
        }

        /// <summary>
        /// Handles executing the login.
        /// </summary>
        /// <param name="context">The context.</param>
        /// <param name="assertion">The assertion.</param>
        private void DoSignOn(IOwinContext context, Saml20Assertion assertion)
        {
            context.Set("Saml2:assertion", assertion);
            var subject = assertion.Subject ?? new SAML2.Schema.Core.NameId();
            Logger.DebugFormat(TraceMessages.SignOnProcessed, assertion.SessionIndex, subject.Value, subject.Format);
        }

    }
}