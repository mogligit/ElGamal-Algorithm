Imports System.Numerics

Public Class ElGamalCiphertext
    Sub New(C1 As BigInteger, ParamArray C2() As BigInteger)
        Me.C1 = C1
        Me.C2 = C2
    End Sub

    Public Property C1 As BigInteger
    Public Property C2 As BigInteger()
End Class