# Authenticator

1. Token Generation  - Done
2. SerialNum - for bulk invalidation - Done
3. Basic Auth
   4. Move Configuration to model/dynamic - Done
      5. Also declare defaults
   5. Login input validation
5. Token Auth
   6. Replace mutex with concurrent map - Not needed mutex is good enough
   7. 
8. Admin token check




git tag -d v1.0.0

version=v1.0.3 && \
git tag $version && git push origin $version  



go get github.com/sudhakar1983/Authenticator@v1.0.3

// go get github.com/sudhakar1983/Configuration@v1.2.4