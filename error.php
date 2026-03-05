<?php  if (count($errors) > 0) : ?>
  <div class="error" style="color: #721c24; background-color: #f8d7da; border: 1px solid #f5c6cb; padding: 10px; border-radius: 5px; margin-bottom: 20px; text-align: left;">
  	<?php foreach ($errors as $error) : ?>
  	  <p style="margin: 0; font-size: 14px;"><?php echo $error ?></p>
  	<?php endforeach ?>
  </div>
<?php  endif ?>
