# Authenticator

1. Token Generation
2. SerialNum - for bulk invalidation
3. Basic Auth
   4. Move Configuration to model/dynamic
      5. Also declare defaults
   5. Login input validation
5. Token Auth
   6. Replace mutex with concurrent map
   7. 





git tag -d v1.0.0

version=v1.1.0 && \
git tag $version && git push origin $version  



go get github.com/sudhakar1983/Authenticator@v1.0.1

// go get github.com/sudhakar1983/Configuration@v1.2.4