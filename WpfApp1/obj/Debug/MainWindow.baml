   M S B A M L   `   `   `  ����B  >WpfApp1, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null!clr-namespace:WpfApp1WpfApp1  5   	       WpfApp1.MainWindow   5   	   \ XPresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35R NWindowsBase, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35W SPresentationCore, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35D 9http://schemas.microsoft.com/winfx/2006/xaml/presentation    5   	   R NSystem.Xaml, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089:x,http://schemas.microsoft.com/winfx/2006/xaml     5   	   @d2http://schemas.microsoft.com/expression/blend/2008     5   	   Jmc;http://schemas.openxmlformats.org/markup-compatibility/2006     5   	   'localclr-namespace:WpfApp1     5   	     � Title$  
MainWindow��5   	   $	��450��6   $	��800��6)   .��5	      �  � ColumnDefinitions 5
   
   �� 5      $	��52* �6   5      �� 5      $
��126* �6   5      �� 5      $	��21* �6   5       � RowDefinitions 5   
   �� 5      $
��370* �6   5      �� 5      $	��53* �6   5      .+�5   
   �� -   5        $��userlist��5      $��0,0,1.5,52.5q�6`   $��2��6v   �� 5   
   -   5        $��
mainbutton��5   7   $��1��6   $��0,0.5,1.5,0.5q�6I   .��6`   Add6e   �� 5   
   -   5        $��messagesSpot��5   $   $��1��6   $��1��68   $��2��6I   
Messages5      �� 5   
   -   5        $��newMsg��5   /   $��1��6   $��1��6   $��0.5,0.5,0,0.5q�6=   .��6T   5!      �� 5"   
   -   5        $��1��5"      $��3��62   .��6B   Send6J   5#      5%      