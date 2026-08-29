$( A minimal Metamath database for harness exercise. $)
$c ( ) -> wff |- $.
$v p q $.
wp $f wff p $.
wq $f wff q $.
wi $a wff ( p -> q ) $.
ax-1 $a |- ( p -> ( q -> p ) ) $.
th1 $p |- ( p -> ( q -> p ) ) $= wp wq ax-1 $.
